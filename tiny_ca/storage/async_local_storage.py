"""
async_local_storage.py

Asynchronous variant of :class:`~tiny_ca.storage.local_storage.LocalStorage`.

All path resolution, validation, serialisation and permission handling is
shared with the synchronous implementation; blocking filesystem calls are run
in a worker thread via :func:`asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil

from cryptography.hazmat.primitives import serialization

from .const import PUBLIC_FILE_MODE, CryptoObject
from .local_storage import LocalStorage, _write_bytes


class AsyncLocalStorage(LocalStorage):
    """
    ``LocalStorage`` with ``async`` ``save_certificate`` /
    ``delete_certificate_folder`` methods.

    Security properties are identical to :class:`LocalStorage`: private keys
    are written with mode ``0600`` and every path component is validated.
    """

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

        See :meth:`LocalStorage.save_certificate` for the full contract.

        Raises
        ------
        FileAlreadyExists
            If the target exists and *is_overwrite* is ``False``.
        InvalidPathError
            If a path component would escape *base_folder*.
        TypeError
            If *cert* is not a supported cryptographic type.
        """
        output_path, data, mode, effective_uuid = await asyncio.to_thread(
            self._prepare,
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
        await self._write_file(
            path=output_path, data=data, is_overwrite=is_overwrite, mode=mode
        )
        self._logger.debug(
            "Saved %s → %s (uuid=%s)", type(cert).__name__, output_path, effective_uuid
        )
        return output_path, effective_uuid

    async def _write_file(  # type: ignore[override]
        self,
        path: Path,
        data: bytes,
        is_overwrite: bool,
        mode: int = PUBLIC_FILE_MODE,
    ) -> None:
        """
        Write *data* to *path* in a worker thread.

        Raises
        ------
        FileAlreadyExists
            If *path* already exists on disk and *is_overwrite* is ``False``.
        """
        await asyncio.to_thread(_write_bytes, path, data, is_overwrite, mode)
        self._logger.debug("Written %d bytes → %s", len(data), path)

    async def delete_certificate_folder(  # type: ignore[override]
        self,
        uuid_str: str,
        cert_path: str | Path | None = None,
    ) -> bool:
        """
        Recursively remove the directory identified by *uuid_str*.

        See :meth:`LocalStorage.delete_certificate_folder` for the contract.
        """
        target = self._delete_target(uuid_str, cert_path)
        if target is None:
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
