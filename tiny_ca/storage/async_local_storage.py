from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from logging import Logger
from pathlib import Path
import shutil
from typing import Any
from uuid import uuid4
import warnings

import aiofiles
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tiny_ca.exc import FileAlreadyExists
from tiny_ca.settings import DEFAULT_LOGGER

from .base_storage import BaseStorage
from .const import CryptoObject
from .local_storage import LocalStorage, _CertSerializer


class AsyncLocalStorage(LocalStorage):
    async def save_certificate(  # type: ignore[override]
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

        cert_data, extension = await asyncio.to_thread(
            _CertSerializer.serialise,
            cert=cert,
            encoding=encoding or self._base_encoding,
            private_format=private_format or self._base_private_format,
            public_format=public_format or self._base_public_format,
            encryption_algorithm=encryption_algorithm
            or self._base_encryption_algorithm,
        )

        output_path = output_dir / f"{file_name}{extension}"
        await self._write_file(
            path=output_path, data=cert_data, is_overwrite=is_overwrite
        )

        self._logger.debug(
            "Saved %s → %s (uuid=%s)", type(cert).__name__, output_path, effective_uuid
        )
        return output_path, effective_uuid

    async def _write_file(  # type: ignore[override]
        self, path: Path, data: bytes, is_overwrite: bool
    ) -> None:
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

        async with aiofiles.open(path, "wb") as fh:
            await fh.write(data)

        self._logger.debug("Written %d bytes → %s", len(data), path)

    async def delete_certificate_folder(  # type: ignore[override]
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
            await asyncio.to_thread(shutil.rmtree, path=target)
            self._logger.info("Deleted certificate folder: %s", target)
            return True
        except OSError as exc:
            self._logger.error(
                "Failed to delete certificate folder %s: %s", target, exc
            )
            return False
