import asyncio
from datetime import UTC, datetime
from logging import Logger
import os
from pathlib import Path

from cryptography import x509

from tiny_ca.ca_factory import CertificateFactory
from tiny_ca.const import CertType
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.db.base_db import BaseDB
from tiny_ca.db.const import CertificateStatus
from tiny_ca.exc import (
    CertNotFound,
    DBNotInitedError,
    NotUniqueCertOwner,
    ValidationCertError,
)
from tiny_ca.models.certtificate import CAConfig, ClientConfig
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.storage import BaseStorage, LocalStorage
from tiny_ca.storage.async_local_storage import AsyncLocalStorage


class AsyncCertLifecycleManager:
    """
    Orchestrates the full lifecycle of X.509 certificates.

    ``CertLifecycleManager`` is the facade that application code interacts with.
    It coordinates four collaborators through dependency injection:

    - ``CertificateFactory`` — cryptographic generation of certificates and CRLs.
    - ``BaseStorage``        — persistent storage of PEM/key/CSR/CRL files.
    - ``BaseDB``             — registration, lookup, revocation, and rotation
                               records in a relational database.
    - ``Logger``             — structured operational logging.

    All three external collaborators are optional at construction time, but
    specific operations will raise ``ValueError`` or ``DBNotInitedError`` if
    a required collaborator is absent when that operation is invoked.

    Parameters
    ----------
    storage : BaseStorage
        File storage backend.  Defaults to ``LocalStorage()`` which writes to
        ``./certs`` relative to the working directory.
    factory : CertificateFactory | None
        Cryptographic factory.  Must be set before calling
        ``issue_certificate``, ``generate_crl``, or ``verify_certificate``.
        Can be set after construction via the ``factory`` property setter.
    db_handler : BaseDB | None
        Database adapter.  When ``None``, all operations that require
        persistence (status lookup, revocation, rotation) will raise
        ``DBNotInitedError``.
    logger : Logger | None
        Logger for operational messages.  Falls back to ``DEFAULT_LOGGER``.

    Raises
    ------
    TypeError
        If *storage* is not a ``BaseStorage`` instance.
    TypeError
        If *db_handler* is provided but is not a ``BaseDB`` instance.
    """

    """
        Orchestrates the full lifecycle of X.509 certificates.

        ``CertLifecycleManager`` is the facade that application code interacts with.
        It coordinates four collaborators through dependency injection:

        - ``CertificateFactory`` — cryptographic generation of certificates and CRLs.
        - ``BaseStorage``        — persistent storage of PEM/key/CSR/CRL files.
        - ``BaseDB``             — registration, lookup, revocation, and rotation
                                   records in a relational database.
        - ``Logger``             — structured operational logging.

        All three external collaborators are optional at construction time, but
        specific operations will raise ``ValueError`` or ``DBNotInitedError`` if
        a required collaborator is absent when that operation is invoked.

        Parameters
        ----------
        storage : BaseStorage
            File storage backend.  Defaults to ``LocalStorage()`` which writes to
            ``./certs`` relative to the working directory.
        factory : CertificateFactory | None
            Cryptographic factory.  Must be set before calling
            ``issue_certificate``, ``generate_crl``, or ``verify_certificate``.
            Can be set after construction via the ``factory`` property setter.
        db_handler : BaseDB | None
            Database adapter.  When ``None``, all operations that require
            persistence (status lookup, revocation, rotation) will raise
            ``DBNotInitedError``.
        logger : Logger | None
            Logger for operational messages.  Falls back to ``DEFAULT_LOGGER``.

        Raises
        ------
        TypeError
            If *storage* is not a ``BaseStorage`` instance.
        TypeError
            If *db_handler* is provided but is not a ``BaseDB`` instance.
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

    # ------------------------------------------------------------------
    # factory property
    # ------------------------------------------------------------------

    @property
    def factory(self) -> CertificateFactory | None:
        """
        The active ``CertificateFactory`` used for certificate issuance.

        Returns
        -------
        CertificateFactory | None
            The current factory, or ``None`` if not yet initialised.
        """
        return self._factory

    @factory.setter
    def factory(self, value: CertificateFactory) -> None:
        """
        Replace the active ``CertificateFactory``.

        Useful for rotating to a new CA without recreating the entire manager.

        Parameters
        ----------
        value : CertificateFactory
            New factory instance to use for subsequent issuance operations.

        Raises
        ------
        TypeError
            If *value* is not a ``CertificateFactory`` instance.
        """
        if not isinstance(value, CertificateFactory):
            raise TypeError(
                f"factory must be a CertificateFactory instance, got {type(value)}"
            )
        self._logger.debug("CertificateFactory replaced: %s", value)
        self._factory = value

    # ------------------------------------------------------------------
    # CA bootstrap
    # ------------------------------------------------------------------

    async def create_self_signed_ca(
        self,
        config: CAConfig,
        cert_path: str | None = None,
        uuid_str: str | None = None,
        is_overwrite: bool = False,
    ) -> tuple[Path, Path]:
        """
        Generate a self-signed root CA certificate and persist both artefacts.

                Delegates cryptographic generation to
                ``CertificateFactory.build_self_signed_ca`` and then saves the
                certificate and private key through the configured ``BaseStorage``.
                When a ``db_handler`` is present the certificate is also registered in
                the database.

                Parameters
                ----------
                config : CAConfig
                    Pydantic model carrying ``common_name``, ``organization``,
                    ``country``, ``key_size``, and ``days_valid``.
                cert_path : str | None
                    Sub-directory under the storage base folder.  ``None`` places the
                    files directly in the base folder.
                uuid_str : str | None
                    Explicit UUID for the storage sub-directory.  ``None`` causes the
                    storage layer to generate one automatically.
                is_overwrite : bool
                    When ``True``, any existing certificate with the same CN is revoked
                    and its files are deleted before the new one is saved.  When
                    ``False`` (default), ``NotUniqueCertOwner`` is raised if a conflict
                    exists.

                Returns
                -------
                tuple[str, str]
                    ``(path_to_cert_pem, path_to_key_pem)`` as returned by the storage
                    layer.

                Examples
                --------
                >>> cert_path, key_path = await mgr.create_self_signed_ca(ca_config)
        """
        self._logger.info(
            "Creating self-signed CA: CN=%s, overwrite=%s",
            config.common_name,
            is_overwrite,
        )

        certificate, private_key = await asyncio.to_thread(
            CertificateFactory.build_self_signed_ca,
            **config.model_dump(),
            logger=self._logger,
        )

        path_to_cert, uuid_str = await self._storage.save_certificate(
            cert=certificate,
            cert_path=cert_path,
            file_name="ca",
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
        )
        path_to_key, uuid_str = await self._storage.save_certificate(
            cert=private_key,
            cert_path=cert_path,
            file_name="ca",
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
        )

        if self._db:
            await self._persist_cert_to_db(
                common_name=config.common_name,
                uuid_str=uuid_str,
                certificate=certificate,
                cert_type=CertType.CA,
                cert_path=cert_path,
                is_overwrite=is_overwrite,
            )

        self._logger.info("CA saved: cert=%s, key=%s", path_to_cert, path_to_key)
        return path_to_cert, path_to_key

    # ------------------------------------------------------------------
    # Certificate issuance
    # ------------------------------------------------------------------

    async def issue_certificate(
        self,
        config: ClientConfig,
        cert_path: str | None = None,
        uuid_str: str | None = None,
        is_overwrite: bool = False,
    ) -> tuple[x509.Certificate, object, x509.CertificateSigningRequest]:
        """
        Issue a new end-entity certificate and persist all three artefacts.

        The method generates the certificate, private key, and CSR via the
        configured ``CertificateFactory``, then saves each file through
        ``BaseStorage``.  If a ``db_handler`` is configured the certificate
        metadata is also written to the database.

        Artefacts written to storage
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        - ``<file_name>.pem``  — the signed certificate.
        - ``<file_name>.key``  — the private key (unencrypted by default).
        - ``<file_name>.csr``  — the certificate signing request (for audit).

        Parameters
        ----------
        config : ClientConfig
            Pydantic model containing all certificate parameters: ``common_name``,
            ``serial_type``, ``key_size``, ``days_valid``, ``email``,
            ``is_server_cert``, ``is_client_cert``, ``san_dns``, ``san_ip``,
            and an optional ``name`` for the output file basename.
        cert_path : str | None
            Sub-directory under the storage base folder.
        uuid_str : str | None
            Explicit UUID; ``None`` auto-generates one.
        is_overwrite : bool
            Allow replacing an existing certificate with the same CN.

        Returns
        -------
        tuple[x509.Certificate, rsa.RSAPrivateKey, x509.CertificateSigningRequest]
            ``(certificate, private_key, csr)`` in-memory objects.

        Raises
        ------
        ValueError
            If ``self.factory`` has not been initialised.
        NotUniqueCertOwner
            If *is_overwrite* is ``False`` and a certificate with the same CN
            already exists in the database.
        """

        self._require_factory()

        file_name = await self._derive_file_name(config)
        self._logger.info(
            "Issuing certificate: CN=%s, file=%s, overwrite=%s",
            config.common_name,
            file_name,
            is_overwrite,
        )

        certificate, private_key, csr = await asyncio.to_thread(
            self._factory.issue_certificate,  # type: ignore[union-attr]
            **config.model_dump(exclude={"name"}),
        )

        path_to_cert, uuid_str = await self._storage.save_certificate(
            cert=certificate,
            cert_path=cert_path,
            file_name=file_name,
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
        )
        path_to_key, uuid_str = await self._storage.save_certificate(
            cert=private_key,
            cert_path=cert_path,
            file_name=file_name,
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
        )
        path_to_csr, uuid_str = await self._storage.save_certificate(
            cert=csr,
            cert_path=cert_path,
            file_name=file_name,
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
        )

        if self._db:
            await self._persist_cert_to_db(
                common_name=config.common_name,
                uuid_str=uuid_str,
                certificate=certificate,
                cert_type=config.serial_type,
                cert_path=cert_path,
                is_overwrite=is_overwrite,
            )

        self._logger.info(
            "Certificate artefacts saved: cert=%s, key=%s, csr=%s",
            path_to_cert,
            path_to_key,
            path_to_csr,
        )
        return certificate, private_key, csr

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    async def revoke_certificate(
        self,
        serial: int,
        reason: x509.ReasonFlags,
    ) -> bool:
        """
        Revoke the certificate identified by *serial*.

        Delegates to ``BaseDB.revoke_certificate``.  The record is updated
        in-place (status → REVOKED, revocation date and reason stored); no
        file is deleted.  Call ``generate_crl`` afterwards to publish the
        updated revocation list.

        Parameters
        ----------
        serial : int
            Integer serial number of the certificate to revoke.
        reason : x509.ReasonFlags
            RFC 5280 revocation reason code (e.g.
            ``x509.ReasonFlags.key_compromise``).

        Returns
        -------
        bool
            ``True`` if the revocation was recorded successfully;
            ``False`` if the operation failed (see logs for details).

        Raises
        ------
        DBNotInitedError
            If no ``db_handler`` was provided at construction time.
        """

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

        return is_success

    # ------------------------------------------------------------------
    # CRL generation
    # ------------------------------------------------------------------

    async def generate_crl(self, days_valid: int = 1) -> x509.CertificateRevocationList:
        """
        Build, sign, and persist a fresh Certificate Revocation List.

        Retrieves all currently-revoked certificates from the database,
        passes them to ``CertificateFactory.build_crl``, and writes the
        resulting CRL to storage as ``crl.pem`` (overwriting any previous
        version — CRLs are always regenerated in-place).

        Parameters
        ----------
        days_valid : int
            Number of days until the CRL's ``nextUpdate`` field.  Relying
            parties will reject the CRL after this point.  Default: ``1``.

        Returns
        -------
        x509.CertificateRevocationList
            The signed CRL object (also persisted to storage).

        Raises
        ------
        DBNotInitedError
            If no ``db_handler`` was provided.
        ValueError
            If ``self.factory`` has not been initialised.
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
            revoked_certs=iter(revoked_rows),
            days_valid=days_valid,
        )
        path, _ = await self._storage.save_certificate(
            cert=crl, file_name="crl", is_overwrite=True, is_add_uuid=False
        )
        self._logger.info("CRL saved to %s", path)
        return crl

    # ------------------------------------------------------------------
    # Status and verification
    # ------------------------------------------------------------------

    async def get_certificate_status(self, serial: int) -> CertificateStatus:
        """
        Determine the current status of the certificate identified by *serial*.

        Looks up the certificate record in the database and evaluates its
        state in the following priority order:
        1. Not found  → ``UNKNOWN``
        2. Revocation date is set → ``REVOKED``
        3. ``not_valid_after`` is in the past → ``EXPIRED``
        4. Otherwise → ``VALID``

        Parameters
        ----------
        serial : int
            Integer serial number of the certificate to check.

        Returns
        -------
        CertificateStatus
            One of ``VALID``, ``REVOKED``, ``EXPIRED``, or ``UNKNOWN``.

        Raises
        ------
        DBNotInitedError
            If no ``db_handler`` was provided.
        """

        self._require_db()

        cert = await self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if not cert:
            return CertificateStatus.UNKNOWN
        if cert.revocation_date:
            return CertificateStatus.REVOKED
        now = datetime.now(UTC)
        if cert.not_valid_after < now:
            return CertificateStatus.EXPIRED
        return CertificateStatus.VALID

    async def verify_certificate(self, cert: x509.Certificate) -> bool:
        """
        Perform a full verification of *cert*: chain, signature, and revocation.

        Combines cryptographic validation (via ``CertificateFactory.validate_cert``)
        with a database revocation check (via ``get_certificate_status``).

        Validation steps
        ~~~~~~~~~~~~~~~~
        1. Issuer field matches the CA subject.
        2. Current UTC time is within the validity window.
        3. Cryptographic signature is valid.
        4. Certificate is not listed as revoked in the database.

        Parameters
        ----------
        cert : x509.Certificate
            The certificate object to verify.

        Returns
        -------
        bool
            ``True`` when all checks pass.

        Raises
        ------
        ValueError
            If ``self.factory`` has not been initialised.
        ValidationCertError
            If the certificate fails any cryptographic check or is revoked.
        """

        self._require_factory()

        self._logger.info("Verifying certificate serial=%s", cert.serial_number)
        await asyncio.to_thread(self._factory.validate_cert, cert=cert)  # type: ignore[union-attr]

        status = await self.get_certificate_status(cert.serial_number)
        if status == CertificateStatus.REVOKED:
            self._logger.warning(
                "Verification failed: certificate serial=%s is revoked",
                cert.serial_number,
            )
            raise ValidationCertError("Certificate is revoked")

        self._logger.info(
            "Certificate serial=%s verified successfully", cert.serial_number
        )
        return True

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    async def rotate_certificate(
        self,
        serial: int,
        config: ClientConfig,
    ) -> tuple[x509.Certificate, object, x509.CertificateSigningRequest]:
        """
        Revoke an existing certificate and issue a replacement in a single operation.

        The old certificate is revoked with reason ``superseded`` before the
        new one is issued.  Both operations are performed against the configured
        ``db_handler``; if the revocation fails an exception is propagated and
        the new certificate is not issued.

        Parameters
        ----------
        serial : int
            Serial number of the certificate to replace.
        config : ClientConfig
            Parameters for the replacement certificate.  The CN may differ
            from the original.

        Returns
        -------
        tuple[x509.Certificate, rsa.RSAPrivateKey, x509.CertificateSigningRequest]
            ``(new_certificate, new_private_key, new_csr)``.

        Raises
        ------
        DBNotInitedError
            If no ``db_handler`` was provided.
        CertNotFound
            If no certificate with *serial* exists in the database.
        ValueError
            If ``self.factory`` has not been initialised.
        """

        self._require_db()

        self._logger.info(
            "Rotating certificate: serial=%d, new_CN=%s", serial, config.common_name
        )

        existing = await self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if not existing:
            self._logger.error("Certificate serial=%d not found for rotation", serial)
            raise CertNotFound()

        await self.revoke_certificate(serial=serial, reason=x509.ReasonFlags.superseded)

        new_cert, new_key, new_csr = await self.issue_certificate(config)
        self._logger.info(
            "Rotation complete: old serial=%d replaced by serial=%s",
            serial,
            new_cert.serial_number,
        )
        return new_cert, new_key, new_csr

    # ------------------------------------------------------------------
    # private helpers
    # ------------------------------------------------------------------

    async def _persist_cert_to_db(
        self,
        common_name: str,
        uuid_str: str,
        certificate: x509.Certificate,
        cert_type: CertType,
        cert_path: str | None,
        is_overwrite: bool,
    ) -> None:
        """
        Register *certificate* in the database, handling CN conflicts.

        If a VALID certificate with *common_name* already exists:
        - *is_overwrite=True*  → the existing cert is revoked (``key_compromise``)
          and its storage folder is deleted before the new record is inserted.
        - *is_overwrite=False* → ``NotUniqueCertOwner`` is raised immediately.

        Parameters
        ----------
        common_name : str
            The CN of the certificate being registered.
        uuid_str : str
            UUID of the storage folder that holds the artefact files.
        certificate : x509.Certificate
            The newly issued certificate object.
        cert_type : CertType
            Category of the certificate (CA, SERVICE, DEVICE, etc.).
        cert_path : str | None
            Base sub-path used by the storage layer; needed when deleting the
            old artefact folder on overwrite.
        is_overwrite : bool
            Whether to replace an existing certificate with the same CN.

        Raises
        ------
        NotUniqueCertOwner
            If *common_name* is already in use and *is_overwrite* is ``False``.
        """

        existing = await self._db.get_by_name(common_name=common_name)  # type: ignore[union-attr]
        print("exis", existing)
        if existing:
            print("exiss")
            if not is_overwrite:
                self._logger.warning(
                    "Duplicate CN detected: CN=%s is already registered", common_name
                )
                raise NotUniqueCertOwner(common_name)

            self._logger.info(
                "Overwriting existing certificate: CN=%s (serial=%s)",
                common_name,
                existing.serial_number,
            )
            await self.revoke_certificate(
                serial=int(existing.serial_number),
                reason=x509.ReasonFlags.key_compromise,
            )
            await self._storage.delete_certificate_folder(
                uuid_str=str(existing.uuid), cert_path=cert_path
            )

        await self._db.register_cert_in_db(  # type: ignore[union-attr]
            cert=certificate, uuid=uuid_str, key_type=cert_type
        )
        self._logger.debug(
            "Certificate registered in DB: CN=%s, uuid=%s", common_name, uuid_str
        )

    @staticmethod
    async def _derive_file_name(config: ClientConfig) -> str:
        return config.name or config.common_name.lower().replace(os.sep, "_")

    def _require_db(self) -> None:
        if not self._db:
            raise DBNotInitedError()

    def _require_factory(self) -> None:
        if not self._factory:
            raise ValueError(
                "factory is not initialised. "
                "Set AsyncCertLifecycleManager.factory before using this operation."
            )
