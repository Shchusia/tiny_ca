"""
base_storage.py

Abstract base class that defines the storage contract for certificate artefacts.

Any class that inherits from ``BaseStorage`` and implements both abstract methods
can be used wherever the application expects a storage backend, without requiring
any changes to the calling code (LSP / DIP).

SOLID notes
-----------
SRP : ``BaseStorage`` declares *what* the storage layer must do; concrete
      subclasses decide *how* (local filesystem, S3, database BLOB, etc.).
OCP : New backends are added by subclassing; existing implementations are
      not modified.
LSP : Subclasses must honour the documented return contracts (e.g. returning
      ``True`` for idempotent deletes rather than raising) so callers can
      substitute them freely.
ISP : The interface is intentionally narrow — exactly the two operations that
      the application layer requires.
DIP : ``CertLifecycleManager`` depends on ``BaseStorage``, never on
      ``LocalStorage`` or any other concrete class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .const import CryptoObject


class BaseStorage(ABC):
    """
    Abstract contract for certificate artefact storage backends.

    Subclasses persist cryptographic objects (certificates, keys, CSRs, CRLs)
    to some durable medium and provide a way to remove an entire issuance
    folder in a single atomic call.

    The two operations map directly to the two storage events in the
    certificate lifecycle:

    - **Issuance** — ``save_certificate`` is called once per artefact
      (``.pem``, ``.key``, ``.csr``) with the same *uuid_str* so all three
      files end up in the same directory.
    - **Revocation / overwrite** — ``delete_certificate_folder`` removes the
      entire UUID directory in one call, avoiding orphaned files.
    """

    @abstractmethod
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
        Serialise *cert* and persist it to the storage backend.

        The implementation must:
        1. Determine the correct serialisation format and file extension from
           the type of *cert* (certificate → ``.pem``, private key → ``.key``,
           CSR → ``.csr``, public key → ``.pub``, CRL → ``.pem``).
        2. Assemble the output path from *cert_path*, the UUID directory
           (when *is_add_uuid* is ``True``), and *file_name* + extension.
        3. Auto-generate a UUID when *uuid_str* is ``None`` and *is_add_uuid*
           is ``True``; reuse *uuid_str* when provided (so that multiple calls
           for the same issuance all land in the same folder).
        4. Honour *is_overwrite*: raise ``FileAlreadyExists`` when ``False``
           and the target path already exists; silently replace when ``True``.
        5. Return the absolute path to the saved file and the UUID used.

        Parameters
        ----------
        cert : CryptoObject
            The cryptographic object to serialise and save.
        file_name : str
            Base filename without extension (e.g. ``"ca"``, ``"my-service"``).
        cert_path : str | Path | None
            Optional sub-directory appended after the backend's root folder.
            ``None`` saves directly under the root.
        uuid_str : str | None
            Explicit UUID for the issuance sub-directory.  Pass the UUID
            returned by a previous call to group multiple artefacts in the
            same folder.  ``None`` triggers auto-generation.
            Ignored when *is_add_uuid* is ``False``.
        encoding : serialization.Encoding | None
            Serialisation encoding override.  ``None`` falls back to the
            implementation's default (typically PEM).
        private_format : serialization.PrivateFormat | None
            Format for private-key serialisation
            (e.g. ``TraditionalOpenSSL``, ``PKCS8``).
            ``None`` uses the implementation default.
        public_format : serialization.PublicFormat | None
            Format for public-key serialisation
            (e.g. ``SubjectPublicKeyInfo``).
            ``None`` uses the implementation default.
        encryption_algorithm : serialization.KeySerializationEncryption | None
            Encryption wrapper for private keys
            (e.g. ``NoEncryption``, ``BestAvailableEncryption``).
            ``None`` uses the implementation default.
        is_add_uuid : bool
            When ``True`` (default), a UUID subdirectory is inserted into the
            path.  Set to ``False`` for singleton files such as CRLs that are
            regenerated in-place (``crl.pem``).
        is_overwrite : bool
            When ``True``, silently replace an existing file at the computed
            path.  When ``False`` (default), raise ``FileAlreadyExists``.

        Returns
        -------
        tuple[Path, str | None]
            ``(absolute_path_to_saved_file, uuid_str_used)``.
            The second element is the UUID that was used (auto-generated or
            the value of *uuid_str*), or ``None`` when *is_add_uuid* is
            ``False``.

        Raises
        ------
        FileAlreadyExists
            If the target file already exists and *is_overwrite* is ``False``.
        TypeError
            If *cert* is not a recognised cryptographic type.
        """

    @abstractmethod
    def delete_certificate_folder(
        self,
        uuid_str: str,
        cert_path: str | Path | None = None,
    ) -> bool:
        """
        Remove the directory that contains all artefacts for a given UUID.

        Implementations must be idempotent: if the target directory does not
        exist, return ``True`` (no action was needed) rather than raising an
        error.  Only genuine unexpected failures (permission errors, I/O
        errors) should return ``False``.

        Parameters
        ----------
        uuid_str : str
            UUID string that identifies the sub-directory to delete.  This is
            the value returned as the second element by ``save_certificate``.
        cert_path : str | Path | None
            Optional sub-path prepended before *uuid_str*, matching the
            *cert_path* used when the artefacts were saved.  ``None`` means
            *uuid_str* is directly under the backend's root folder.

        Returns
        -------
        bool
            ``True``  — the directory was deleted, or did not exist (idempotent).
            ``False`` — an unexpected error occurred during deletion; the
                        implementation must log the exception.
        """
