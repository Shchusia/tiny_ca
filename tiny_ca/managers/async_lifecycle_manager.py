"""
async_lifecycle_manager.py

Asynchronous counterpart of :class:`~tiny_ca.managers.CertLifecycleManager`.

Behaviour, consistency rules and error semantics are identical to the
synchronous manager (see its module docstring); CPU-bound cryptography runs
in worker threads via :func:`asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from logging import Logger
from pathlib import Path
import warnings

from cryptography import x509

from tiny_ca import CertificateRecord
from tiny_ca.ca_factory import CertificateFactory
from tiny_ca.ca_factory.utils.life_time import CertLifetime
from tiny_ca.const import CertType, KeyAlgorithm
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.db.const import CertificateStatus, RevokeStatus
from tiny_ca.db.utils import certificate_common_name
from tiny_ca.exc import (
    CertNotFound,
    CertRevocationError,
    DBNotInitedError,
    DBOperationError,
    NotUniqueCertOwner,
    ValidationCertError,
)
from tiny_ca.models.certificate import CAConfig, CertificateDetails, ClientConfig
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.storage.async_local_storage import AsyncLocalStorage
from tiny_ca.storage.const import CryptoObject
from tiny_ca.utils.keys import PrivateKey
from tiny_ca.utils.serial_generator import SerialWithEncoding

from .sync_lifecycle_manager import cert_type_from_record, safe_file_name


class AsyncCertLifecycleManager:
    """
    Orchestrates the full lifecycle of X.509 certificates (asyncio).

    Parameters
    ----------
    storage : AsyncLocalStorage | None
        Async storage backend.  ``None`` creates ``AsyncLocalStorage()``.
    factory : CertificateFactory | None
        Cryptographic factory; can be set later via the ``factory`` property.
    db_handler : AsyncDBHandler | None
        Async database adapter.
    logger : Logger | None
        Logger for operational messages.  Falls back to ``DEFAULT_LOGGER``.
    """

    def __init__(
        self,
        storage: AsyncLocalStorage | None = None,
        factory: CertificateFactory | None = None,
        db_handler: AsyncDBHandler | None = None,
        logger: Logger | None = None,
    ) -> None:
        self._storage = storage or AsyncLocalStorage()
        self._db = db_handler
        self._factory = factory
        self._logger = logger or DEFAULT_LOGGER

    @property
    def factory(self) -> CertificateFactory | None:
        """The active ``CertificateFactory`` (``None`` if not yet set)."""
        return self._factory

    @factory.setter
    def factory(self, value: CertificateFactory) -> None:
        """Replace the active factory; raises ``TypeError`` on a wrong type."""
        if not isinstance(value, CertificateFactory):
            raise TypeError(
                f"factory must be a CertificateFactory instance, got {type(value)}"
            )
        self._logger.debug("CertificateFactory replaced: %s", value)
        self._factory = value

    # ------------------------------------------------------------------
    # CA bootstrap / issuance
    # ------------------------------------------------------------------

    async def create_self_signed_ca(
        self,
        config: CAConfig,
        cert_path: str | None = None,
        uuid_str: str | None = None,
        is_overwrite: bool = False,
    ) -> tuple[Path, Path]:
        """Async version of ``CertLifecycleManager.create_self_signed_ca``."""
        self._logger.info(
            "Creating self-signed CA: CN=%s, overwrite=%s",
            config.common_name,
            is_overwrite,
        )
        replaced = await self._find_conflict(config.common_name, is_overwrite)
        certificate, private_key = await asyncio.to_thread(
            CertificateFactory.build_self_signed_ca,
            **config.model_dump(),
            logger=self._logger,
        )
        paths, _ = await self._store_and_register(
            artefacts=[(certificate, "ca"), (private_key, "ca")],
            certificate=certificate,
            cert_type=CertType.CA,
            cert_path=cert_path,
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
            replaced=replaced,
            delete_replaced_folder=True,
        )
        self._logger.info("CA saved: cert=%s, key=%s", paths[0], paths[1])
        return paths[0], paths[1]

    async def issue_certificate(
        self,
        config: ClientConfig,
        cert_path: str | None = None,
        uuid_str: str | None = None,
        is_overwrite: bool = False,
    ) -> tuple[x509.Certificate, PrivateKey, x509.CertificateSigningRequest]:
        """Async version of ``CertLifecycleManager.issue_certificate``."""
        self._require_factory()
        file_name = await self._derive_file_name(config)
        self._logger.info(
            "Issuing certificate: CN=%s, file=%s, overwrite=%s",
            config.common_name,
            file_name,
            is_overwrite,
        )
        replaced = await self._find_conflict(config.common_name, is_overwrite)
        return await self._issue(
            config,
            file_name=file_name,
            cert_path=cert_path,
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
            replaced=replaced,
            delete_replaced_folder=True,
        )

    # ------------------------------------------------------------------
    # Revocation / CRL
    # ------------------------------------------------------------------

    async def revoke_certificate(self, serial: int, reason: x509.ReasonFlags) -> bool:
        """Async version of ``CertLifecycleManager.revoke_certificate``."""
        self._require_db()
        self._logger.info("Revoking certificate: serial=%d, reason=%s", serial, reason)
        is_success, status = await self._db.revoke_certificate(  # type: ignore[union-attr]
            serial_number=serial, reason=reason
        )
        if not is_success:
            self._logger.warning(
                "Failed to revoke certificate serial=%d: %s", serial, status
            )
        else:
            self._logger.info("Certificate serial=%d revoked successfully", serial)
        return bool(is_success)

    async def generate_crl(
        self,
        cert_path: str | None = None,
        days_valid: int = 1,
        crl_number: int | None = None,
    ) -> x509.CertificateRevocationList:
        """
        Async version of ``CertLifecycleManager.generate_crl``.

        All revoked rows are collected first; a database error aborts the
        operation (no partial / empty CRL is ever written).
        """
        self._require_db()
        self._require_factory()
        self._logger.info("Generating CRL: days_valid=%d", days_valid)
        revoked_rows = [
            row
            async for row in self._db.get_revoked_certificates()  # type: ignore[union-attr]
        ]
        crl = await asyncio.to_thread(
            self._factory.build_crl,  # type: ignore[union-attr]
            revoked_certs=revoked_rows,
            days_valid=days_valid,
            crl_number=crl_number,
        )
        path, _ = await self._storage.save_certificate(
            cert_path=cert_path,
            cert=crl,
            file_name="crl",
            is_overwrite=True,
            is_add_uuid=False,
        )
        self._logger.info("CRL saved to %s", path)
        return crl

    # ------------------------------------------------------------------
    # Status and verification
    # ------------------------------------------------------------------

    async def get_certificate_status(self, serial: int) -> CertificateStatus:
        """Async version of ``CertLifecycleManager.get_certificate_status``."""
        self._require_db()
        cert = await self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if not cert:
            return CertificateStatus.UNKNOWN
        if cert.revocation_date or cert.status == CertificateStatus.REVOKED:
            return CertificateStatus.REVOKED
        now = datetime.now(UTC)
        not_valid_after = CertLifetime.normalize_dt(cert.not_valid_after)
        if not_valid_after < now:
            return CertificateStatus.EXPIRED
        return CertificateStatus.VALID

    async def verify_certificate(
        self,
        cert: x509.Certificate,
        intermediates: Sequence[x509.Certificate] | None = None,
    ) -> bool:
        """
        Async version of ``CertLifecycleManager.verify_certificate``:
        REVOKED certificates and UNKNOWN certificates issued directly by this
        CA are rejected; database errors propagate.
        """
        self._require_factory()
        self._require_db()
        factory = self._factory

        self._logger.info("Verifying certificate serial=%s", cert.serial_number)
        root: x509.Certificate | None
        if intermediates:
            path = await asyncio.to_thread(factory.validate_chain, cert, intermediates)
            root, to_check = path[-1], path[:-1]
        else:
            await asyncio.to_thread(factory.validate_cert, cert=cert)
            root, to_check = None, [cert]

        for item in to_check:
            status = await self.get_certificate_status(item.serial_number)
            if status == CertificateStatus.REVOKED:
                self._logger.warning(
                    "Verification failed: certificate serial=%s is revoked",
                    item.serial_number,
                )
                raise ValidationCertError("Certificate is revoked")
            issued_by_root = root is None or item.issuer == root.subject
            if status == CertificateStatus.UNKNOWN and issued_by_root:
                self._logger.warning(
                    "Verification failed: certificate serial=%s is not registered",
                    item.serial_number,
                )
                raise ValidationCertError(
                    "Certificate is not registered in this CA's registry"
                )

        self._logger.info(
            "Certificate serial=%s verified successfully", cert.serial_number
        )
        return True

    # ------------------------------------------------------------------
    # Rotation / renewal
    # ------------------------------------------------------------------

    async def rotate_certificate(
        self,
        serial: int,
        config: ClientConfig,
        cert_path: str | None = None,
    ) -> tuple[x509.Certificate, PrivateKey, x509.CertificateSigningRequest]:
        """Async version of ``CertLifecycleManager.rotate_certificate``."""
        self._require_db()
        self._require_factory()
        self._logger.info(
            "Rotating certificate: serial=%d, new_CN=%s", serial, config.common_name
        )
        existing = await self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if not existing:
            self._logger.error("Certificate serial=%d not found for rotation", serial)
            raise CertNotFound()

        await self._find_conflict(
            config.common_name, is_overwrite=False, exclude=serial
        )
        new_cert, new_key, new_csr = await self._issue(
            config,
            file_name=await self._derive_file_name(config),
            cert_path=cert_path,
            uuid_str=None,
            is_overwrite=False,
            replaced=existing,
            delete_replaced_folder=False,
        )
        self._logger.info(
            "Rotation complete: old serial=%d replaced by serial=%s",
            serial,
            new_cert.serial_number,
        )
        return new_cert, new_key, new_csr

    async def renew_certificate(
        self,
        serial: int,
        days_valid: int = 365,
        valid_from: datetime | None = None,
        cert_path: str | None = None,
    ) -> x509.Certificate:
        """Async version of ``CertLifecycleManager.renew_certificate``."""
        self._require_db()
        self._require_factory()
        record = await self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if record is None:
            raise CertNotFound()

        cert_obj = x509.load_pem_x509_certificate(record.certificate_pem.encode())
        renewed = await asyncio.to_thread(
            self._factory.renew_certificate,  # type: ignore[union-attr]
            cert=cert_obj,
            days_valid=days_valid,
            valid_from=valid_from,
        )
        common_name = certificate_common_name(renewed)
        await self._find_conflict(common_name, is_overwrite=False, exclude=serial)
        await self._store_and_register(
            artefacts=[(renewed, safe_file_name(common_name, "renewed"))],
            certificate=renewed,
            cert_type=cert_type_from_record(record),
            cert_path=cert_path,
            uuid_str=None,
            is_overwrite=False,
            replaced=record,
            delete_replaced_folder=False,
        )
        self._logger.info(
            "Certificate renewed: serial=%d → new_serial=%s",
            serial,
            renewed.serial_number,
        )
        return renewed

    # ------------------------------------------------------------------
    # Other factory operations
    # ------------------------------------------------------------------

    async def inspect_certificate(self, cert: x509.Certificate) -> CertificateDetails:
        """Structured summary of *cert*."""
        self._require_factory()
        return await asyncio.to_thread(self._factory.inspect_certificate, cert)  # type: ignore[union-attr]

    async def cosign_certificate(
        self,
        cert: x509.Certificate,
        days_valid: int | None = None,
        valid_from: datetime | None = None,
        serial_type: CertType | None = None,
        cert_path: str | None = None,
        is_overwrite: bool = False,
    ) -> x509.Certificate:
        """Async version of ``CertLifecycleManager.cosign_certificate``."""
        self._require_factory()
        cosigned = await asyncio.to_thread(
            self._factory.cosign_certificate,  # type: ignore[union-attr]
            cert=cert,
            days_valid=days_valid,
            valid_from=valid_from,
            serial_type=serial_type,
        )
        common_name = certificate_common_name(cosigned)
        replaced = await self._find_conflict(common_name, is_overwrite)
        cert_type = SerialWithEncoding.parse(cosigned.serial_number)[0]
        await self._store_and_register(
            artefacts=[(cosigned, safe_file_name(common_name, "cosigned"))],
            certificate=cosigned,
            cert_type=cert_type or CertType.SERVICE,
            cert_path=cert_path,
            uuid_str=None,
            is_overwrite=is_overwrite,
            replaced=replaced,
            delete_replaced_folder=True,
        )
        return cosigned

    async def export_pkcs12(
        self,
        cert: x509.Certificate,
        private_key: PrivateKey,
        password: bytes | None = None,
        name: str | None = None,
    ) -> bytes:
        """Pack cert + key into a PKCS#12 bundle."""
        self._require_factory()
        return await asyncio.to_thread(
            self._factory.export_pkcs12,  # type: ignore[union-attr]
            cert=cert,
            private_key=private_key,
            password=password,
            name=name,
        )

    async def get_cert_chain(self, cert: x509.Certificate) -> list[x509.Certificate]:
        """Return the ``[cert, ca_cert]`` chain."""
        self._require_factory()
        return await asyncio.to_thread(self._factory.get_cert_chain, cert)  # type: ignore[union-attr]

    async def issue_intermediate_ca(
        self,
        common_name: str,
        key_size: int = 4096,
        days_valid: int = 1825,
        valid_from: datetime | None = None,
        path_length: int | None = 0,
        organization: str | None = None,
        country: str | None = None,
        cert_path: str | None = None,
        uuid_str: str | None = None,
        key_algorithm: KeyAlgorithm = KeyAlgorithm.RSA,
        is_overwrite: bool = False,
    ) -> tuple[x509.Certificate, PrivateKey]:
        """Async version of ``CertLifecycleManager.issue_intermediate_ca``."""
        self._require_factory()
        replaced = await self._find_conflict(common_name, is_overwrite)
        cert, key = await asyncio.to_thread(
            self._factory.issue_intermediate_ca,  # type: ignore[union-attr]
            common_name=common_name,
            key_size=key_size,
            days_valid=days_valid,
            valid_from=valid_from,
            path_length=path_length,
            organization=organization,
            country=country,
            key_algorithm=key_algorithm,
        )
        await self._store_and_register(
            artefacts=[(cert, "intermediate_ca"), (key, "intermediate_ca")],
            certificate=cert,
            cert_type=CertType.CA,
            cert_path=cert_path,
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
            replaced=replaced,
            delete_replaced_folder=True,
        )
        return cert, key

    async def list_certificates(
        self,
        status: str | None = None,
        key_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CertificateRecord]:
        """Return paginated certificate records. Requires db_handler."""
        self._require_db()
        return await self._db.list_all(  # type: ignore[union-attr]
            status=status, key_type=key_type, limit=limit, offset=offset
        )

    async def get_expiring_soon(self, within_days: int = 30) -> list[CertificateRecord]:
        """Return VALID certs expiring within *within_days* days."""
        self._require_db()
        return await self._db.get_expiring(within_days=within_days)  # type: ignore[union-attr]

    async def delete_certificate(
        self, serial: int, cert_path: str | None = None
    ) -> bool:
        """Hard-delete a certificate from the DB and its folder from storage."""
        self._require_db()
        record = await self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if record is None:
            return False
        uuid = record.uuid
        deleted = await self._db.delete_by_uuid(uuid=uuid)  # type: ignore[union-attr]
        if deleted and uuid:
            await self._storage.delete_certificate_folder(
                uuid_str=uuid, cert_path=cert_path
            )
        return bool(deleted)

    async def refresh_expired_statuses(self) -> int:
        """Bulk-mark expired certificates. Returns count of updated rows."""
        self._require_db()
        return await self._db.update_status_expired()  # type: ignore[union-attr]

    async def verify_crl(self, crl: x509.CertificateRevocationList) -> None:
        """Verify CRL signature and expiry."""
        self._require_factory()
        await asyncio.to_thread(self._factory.verify_crl, crl)  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Private helpers (mirror the synchronous manager)
    # ------------------------------------------------------------------

    async def _issue(
        self,
        config: ClientConfig,
        *,
        file_name: str,
        cert_path: str | None,
        uuid_str: str | None,
        is_overwrite: bool,
        replaced: CertificateRecord | None,
        delete_replaced_folder: bool,
    ) -> tuple[x509.Certificate, PrivateKey, x509.CertificateSigningRequest]:
        certificate, private_key, csr = await asyncio.to_thread(
            self._factory.issue_certificate,  # type: ignore[union-attr]
            **config.model_dump(exclude={"name"}),
        )
        paths, _ = await self._store_and_register(
            artefacts=[
                (certificate, file_name),
                (private_key, file_name),
                (csr, file_name),
            ],
            certificate=certificate,
            cert_type=config.serial_type,
            cert_path=cert_path,
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
            replaced=replaced,
            delete_replaced_folder=delete_replaced_folder,
        )
        self._logger.info(
            "Certificate artefacts saved: cert=%s, key=%s, csr=%s", *paths
        )
        return certificate, private_key, csr

    async def _find_conflict(
        self,
        common_name: str,
        is_overwrite: bool,
        exclude: int | None = None,
    ) -> CertificateRecord | None:
        """See ``CertLifecycleManager._find_conflict``."""
        if not self._db:
            return None
        existing = await self._db.get_by_name(common_name=common_name)
        if existing is None:
            return None
        if exclude is not None and int(existing.serial_number) == exclude:
            return None
        if not is_overwrite:
            self._logger.warning(
                "Duplicate CN detected: CN=%s is already registered", common_name
            )
            raise NotUniqueCertOwner(common_name)
        return existing

    async def _store_and_register(
        self,
        *,
        artefacts: Sequence[tuple[CryptoObject, str]],
        certificate: x509.Certificate,
        cert_type: CertType,
        cert_path: str | None,
        uuid_str: str | None,
        is_overwrite: bool,
        replaced: CertificateRecord | None,
        delete_replaced_folder: bool,
    ) -> tuple[list[Path], str | None]:
        """See ``CertLifecycleManager._store_and_register``."""
        paths: list[Path] = []
        effective_uuid = uuid_str
        try:
            for obj, name in artefacts:
                path, effective_uuid = await self._storage.save_certificate(
                    cert=obj,
                    cert_path=cert_path,
                    file_name=name,
                    uuid_str=effective_uuid,
                    is_overwrite=is_overwrite,
                )
                paths.append(path)
            if self._db and not await self._db.register_cert_in_db(
                cert=certificate, uuid=str(effective_uuid), key_type=cert_type
            ):
                raise DBOperationError(
                    "register_cert_in_db",
                    f"certificate serial={certificate.serial_number} was not stored",
                )
        except Exception:
            await self._discard(paths, effective_uuid, uuid_str is None, cert_path)
            raise

        if replaced is not None and self._db:
            ok, status = await self._db.revoke_certificate(
                serial_number=int(replaced.serial_number),
                reason=x509.ReasonFlags.superseded,
            )
            if not ok and status is not RevokeStatus.NOT_FOUND:
                await self._db.delete_by_uuid(uuid=str(effective_uuid))
                await self._discard(paths, effective_uuid, uuid_str is None, cert_path)
                raise CertRevocationError(
                    int(replaced.serial_number), getattr(status, "value", str(status))
                )
            if (
                delete_replaced_folder
                and replaced.uuid
                and str(replaced.uuid) != str(effective_uuid)
            ):
                await self._storage.delete_certificate_folder(
                    uuid_str=str(replaced.uuid), cert_path=cert_path
                )
        return paths, effective_uuid

    async def _discard(
        self,
        paths: list[Path],
        uuid_str: str | None,
        folder_created: bool,
        cert_path: str | None,
    ) -> None:
        """Best-effort removal of artefacts written by a failed operation."""
        if not paths:
            return
        try:
            if folder_created and uuid_str:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    await self._storage.delete_certificate_folder(
                        uuid_str=uuid_str, cert_path=cert_path
                    )
            else:
                for path in paths:
                    await asyncio.to_thread(Path(path).unlink, missing_ok=True)
        except Exception as exc:  # pragma: no cover - best effort
            self._logger.error("Failed to clean up artefacts %s: %s", paths, exc)

    @staticmethod
    async def _derive_file_name(config: ClientConfig) -> str:
        """Storage basename: ``config.name`` or the CN made safe."""
        return config.name or safe_file_name(config.common_name)

    def _require_db(self) -> None:
        if not self._db:
            raise DBNotInitedError()

    def _require_factory(self) -> None:
        if not self._factory:
            raise ValueError(
                "factory is not initialised. "
                "Set AsyncCertLifecycleManager.factory before using this operation."
            )
