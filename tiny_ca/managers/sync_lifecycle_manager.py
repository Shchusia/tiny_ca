"""
sync_lifecycle_manager.py

High-level orchestrator for the X.509 certificate lifecycle.

This module is the single entry-point for application code that needs to
issue, store, revoke, rotate, or verify certificates.  It delegates every
specialised concern to the appropriate collaborator:

- Cryptographic generation  → ``CertificateFactory``
- File persistence          → ``BaseStorage``
- Database registration     → ``BaseDB``

Consistency rules
-----------------
- Every certificate signed by the CA through this manager (issue, renew,
  co-sign, intermediate CA, self-signed CA) is registered in the database
  when one is configured, so it can be revoked and appears in the CRL.
- CN conflicts are detected *before* anything is written to storage.
- If registration fails, the artefacts written for the operation are removed
  and the error is raised — no orphaned private keys on disk.
- A certificate that is replaced (overwrite, rotation, renewal) is revoked
  with reason ``superseded``; if that revocation fails, the new certificate
  is rolled back and ``CertRevocationError`` is raised.

SOLID notes
-----------
SRP : ``CertLifecycleManager`` coordinates operations; it contains no
      cryptographic logic, no SQL, and no file I/O of its own.
OCP : New storage backends and database adapters plug in without changing
      this class.
LSP : ``BaseStorage`` and ``BaseDB`` dependencies are fully substitutable.
DIP : All three collaborators are injected at construction time.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from logging import Logger
from pathlib import Path
import re
import warnings

from cryptography import x509

from tiny_ca import CertificateRecord
from tiny_ca.ca_factory import CertificateFactory
from tiny_ca.ca_factory.utils.life_time import CertLifetime
from tiny_ca.const import CertType, KeyAlgorithm
from tiny_ca.db.base_db import BaseDB
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
from tiny_ca.storage import BaseStorage, LocalStorage
from tiny_ca.storage.const import CryptoObject
from tiny_ca.utils.keys import PrivateKey
from tiny_ca.utils.serial_generator import SerialWithEncoding

_UNSAFE_FILE_CHARS = re.compile(r"[\\/\x00]")


def safe_file_name(text: str, default: str = "cert") -> str:
    """
    Derive a storage file basename from a CN.

    Path separators and NUL are replaced with ``_`` and leading dots are
    stripped, so the result can never point outside the storage folder.
    """
    return _UNSAFE_FILE_CHARS.sub("_", text.lower()).lstrip(".") or default


def cert_type_from_record(record: CertificateRecord) -> CertType:
    """``CertType`` stored in *record*, defaulting to ``SERVICE``."""
    try:
        return CertType(record.key_type)
    except ValueError:
        return CertType.SERVICE


class CertLifecycleManager:
    """
    Orchestrates the full lifecycle of X.509 certificates.

    Parameters
    ----------
    storage : BaseStorage | None
        File storage backend.  ``None`` creates a ``LocalStorage()`` writing
        to ``./certs`` (a new instance per manager).
    factory : CertificateFactory | None
        Cryptographic factory.  Must be set before issuing, generating CRLs or
        verifying.  Can be set later via the ``factory`` property.
    db_handler : BaseDB | None
        Database adapter.  When ``None``, operations that require persistence
        (status lookup, revocation, rotation, renewal) raise
        ``DBNotInitedError``.
    logger : Logger | None
        Logger for operational messages.  Falls back to ``DEFAULT_LOGGER``.

    Raises
    ------
    TypeError
        If *storage* is not a ``BaseStorage`` instance, or *db_handler* is
        provided but is not a ``BaseDB`` instance.
    """

    def __init__(
        self,
        storage: BaseStorage | None = None,
        factory: CertificateFactory | None = None,
        db_handler: BaseDB | None = None,
        logger: Logger | None = None,
    ) -> None:
        if storage is None:
            storage = LocalStorage()
        if not isinstance(storage, BaseStorage):
            raise TypeError(
                f"storage must be a BaseStorage instance, got {type(storage)}"
            )
        if db_handler is not None and not isinstance(db_handler, BaseDB):
            raise TypeError(
                f"db_handler must be a BaseDB instance, got {type(db_handler)}"
            )

        self._storage = storage
        self._db = db_handler
        self._factory = factory
        self._logger = logger or DEFAULT_LOGGER

    # ------------------------------------------------------------------
    # factory property (DIP: allows late injection / substitution)
    # ------------------------------------------------------------------

    @property
    def factory(self) -> CertificateFactory | None:
        """The active ``CertificateFactory`` (``None`` if not yet set)."""
        return self._factory

    @factory.setter
    def factory(self, value: CertificateFactory) -> None:
        """
        Replace the active ``CertificateFactory``.

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

    def create_self_signed_ca(
        self,
        config: CAConfig,
        cert_path: str | None = None,
        uuid_str: str | None = None,
        is_overwrite: bool = False,
    ) -> tuple[Path, Path]:
        """
        Generate a self-signed root CA certificate and persist both artefacts.

        Parameters
        ----------
        config : CAConfig
            CA parameters (CN, organisation, country, key algorithm / size,
            validity).
        cert_path : str | None
            Sub-directory under the storage base folder.
        uuid_str : str | None
            Explicit UUID for the storage sub-directory.
        is_overwrite : bool
            When ``True``, an existing VALID certificate with the same CN is
            revoked (``superseded``) and its files are deleted.  When
            ``False`` (default), ``NotUniqueCertOwner`` is raised *before*
            anything is written.

        Returns
        -------
        tuple[Path, Path]
            ``(path_to_cert_pem, path_to_key)``.
        """
        self._logger.info(
            "Creating self-signed CA: CN=%s, overwrite=%s",
            config.common_name,
            is_overwrite,
        )
        replaced = self._find_conflict(config.common_name, is_overwrite)

        certificate, private_key = CertificateFactory.build_self_signed_ca(
            **config.model_dump(), logger=self._logger
        )
        paths, _ = self._store_and_register(
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

    # ------------------------------------------------------------------
    # Certificate issuance
    # ------------------------------------------------------------------

    def issue_certificate(
        self,
        config: ClientConfig,
        cert_path: str | None = None,
        uuid_str: str | None = None,
        is_overwrite: bool = False,
    ) -> tuple[x509.Certificate, PrivateKey, x509.CertificateSigningRequest]:
        """
        Issue a new end-entity certificate and persist all artefacts.

        Saves ``<file_name>.pem`` (certificate), ``<file_name>.key`` (private
        key, mode 0600) and ``<file_name>.csr`` into a dedicated UUID folder,
        then registers the certificate in the database.

        Parameters
        ----------
        config : ClientConfig
            Certificate parameters.
        cert_path : str | None
            Sub-directory under the storage base folder.
        uuid_str : str | None
            Explicit UUID for the storage sub-directory.
        is_overwrite : bool
            Replace an existing VALID certificate with the same CN (it is
            revoked with reason ``superseded`` and its folder deleted).

        Returns
        -------
        tuple[x509.Certificate, PrivateKey, x509.CertificateSigningRequest]
            ``(certificate, private_key, csr)``.

        Raises
        ------
        ValueError
            If ``self.factory`` has not been initialised.
        NotUniqueCertOwner
            If the CN is already in use and *is_overwrite* is ``False``.
            Nothing is written in that case.
        DBOperationError
            If the database cannot be read or the certificate cannot be
            registered (written artefacts are removed).
        """
        self._require_factory()
        file_name = self._derive_file_name(config)
        self._logger.info(
            "Issuing certificate: CN=%s, file=%s, overwrite=%s",
            config.common_name,
            file_name,
            is_overwrite,
        )
        replaced = self._find_conflict(config.common_name, is_overwrite)
        return self._issue(
            config,
            file_name=file_name,
            cert_path=cert_path,
            uuid_str=uuid_str,
            is_overwrite=is_overwrite,
            replaced=replaced,
            delete_replaced_folder=True,
        )

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke_certificate(
        self,
        serial: int,
        reason: x509.ReasonFlags,
    ) -> bool:
        """
        Revoke the certificate identified by *serial*.

        The record is updated in place (status → REVOKED, date and reason
        stored).  Call ``generate_crl`` afterwards to publish the change.

        Returns
        -------
        bool
            ``True`` if the revocation was recorded; ``False`` otherwise
            (see logs for details).

        Raises
        ------
        DBNotInitedError
            If no ``db_handler`` was provided.
        """
        self._require_db()
        self._logger.info("Revoking certificate: serial=%d, reason=%s", serial, reason)

        is_success, status = self._db.revoke_certificate(  # type: ignore[union-attr]
            serial_number=serial, reason=reason
        )
        if not is_success:
            self._logger.warning(
                "Failed to revoke certificate serial=%d: %s", serial, status
            )
        else:
            self._logger.info("Certificate serial=%d revoked successfully", serial)

        return bool(is_success)

    # ------------------------------------------------------------------
    # CRL generation
    # ------------------------------------------------------------------

    def generate_crl(
        self,
        cert_path: str | None = None,
        days_valid: int = 1,
        crl_number: int | None = None,
    ) -> x509.CertificateRevocationList:
        """
        Build, sign, and persist a fresh Certificate Revocation List.

        Writes ``crl.pem`` to storage (overwriting the previous version).

        Parameters
        ----------
        cert_path : str | None
            Sub-directory under the storage base folder.
        days_valid : int
            Days until the CRL's ``nextUpdate``.  Default: ``1``.
        crl_number : int | None
            Explicit CRL number; ``None`` derives a monotonic one from time.

        Raises
        ------
        DBNotInitedError
            If no ``db_handler`` was provided.
        DBOperationError
            If revoked certificates cannot be read — no CRL is produced.
        ValueError
            If ``self.factory`` has not been initialised.
        """
        self._require_db()
        self._require_factory()

        self._logger.info("Generating CRL: days_valid=%d", days_valid)
        revoked_certs = self._db.get_revoked_certificates()  # type: ignore[union-attr]

        crl = self._factory.build_crl(  # type: ignore[union-attr]
            revoked_certs=revoked_certs, days_valid=days_valid, crl_number=crl_number
        )
        path, _ = self._storage.save_certificate(
            cert=crl,
            cert_path=cert_path,
            file_name="crl",
            is_overwrite=True,
            is_add_uuid=False,
        )
        self._logger.info("CRL saved to %s", path)
        return crl

    # ------------------------------------------------------------------
    # Status and verification
    # ------------------------------------------------------------------

    def get_certificate_status(self, serial: int) -> CertificateStatus:
        """
        Determine the current status of the certificate identified by *serial*.

        Priority: not found → ``UNKNOWN``; revoked → ``REVOKED``; past
        ``not_valid_after`` → ``EXPIRED``; otherwise ``VALID``.

        Raises
        ------
        DBNotInitedError
            If no ``db_handler`` was provided.
        DBOperationError
            If the database cannot be read.
        """
        self._require_db()

        cert = self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if not cert:
            return CertificateStatus.UNKNOWN
        if cert.revocation_date or cert.status == CertificateStatus.REVOKED:
            return CertificateStatus.REVOKED
        now = datetime.now(UTC)
        not_valid_after = CertLifetime.normalize_dt(cert.not_valid_after)

        if not_valid_after < now:
            return CertificateStatus.EXPIRED
        return CertificateStatus.VALID

    def verify_certificate(
        self,
        cert: x509.Certificate,
        intermediates: Sequence[x509.Certificate] | None = None,
    ) -> bool:
        """
        Fully verify *cert*: chain, signature, validity and revocation.

        Steps
        ~~~~~
        1. Cryptographic validation — ``validate_cert`` (issued directly by
           this CA) or ``validate_chain`` when *intermediates* are given.
        2. Registry check for every certificate in the path:
           - ``REVOKED`` anywhere → rejected;
           - a certificate issued directly by this CA must be registered
             (``UNKNOWN`` → rejected: it was not issued through this
             registry, so its revocation status cannot be known).

        Database errors propagate (fail closed).

        Returns
        -------
        bool
            ``True`` when all checks pass.

        Raises
        ------
        ValueError
            If ``self.factory`` has not been initialised.
        DBNotInitedError
            If no ``db_handler`` was provided.
        ValidationCertError
            If any check fails.
        """
        self._require_factory()
        self._require_db()
        factory = self._factory

        self._logger.info("Verifying certificate serial=%s", cert.serial_number)
        if intermediates:
            path = factory.validate_chain(cert, intermediates)
            root, to_check = path[-1], path[:-1]
        else:
            factory.validate_cert(cert=cert)
            root, to_check = None, [cert]

        for item in to_check:
            self._check_registry_status(item, root)

        self._logger.info(
            "Certificate serial=%s verified successfully", cert.serial_number
        )
        return True

    def _check_registry_status(
        self, cert: x509.Certificate, root: x509.Certificate | None
    ) -> None:
        status = self.get_certificate_status(cert.serial_number)
        if status == CertificateStatus.REVOKED:
            self._logger.warning(
                "Verification failed: certificate serial=%s is revoked",
                cert.serial_number,
            )
            raise ValidationCertError("Certificate is revoked")
        issued_by_root = root is None or cert.issuer == root.subject
        if status == CertificateStatus.UNKNOWN and issued_by_root:
            self._logger.warning(
                "Verification failed: certificate serial=%s is not registered",
                cert.serial_number,
            )
            raise ValidationCertError(
                "Certificate is not registered in this CA's registry"
            )

    # ------------------------------------------------------------------
    # Rotation / renewal
    # ------------------------------------------------------------------

    def rotate_certificate(
        self,
        serial: int,
        config: ClientConfig,
        cert_path: str | None = None,
    ) -> tuple[x509.Certificate, PrivateKey, x509.CertificateSigningRequest]:
        """
        Replace an existing certificate with a newly issued one (new key pair).

        The replacement is issued and registered first; then the old
        certificate is revoked with reason ``superseded``.  If that revocation
        fails, the replacement is rolled back and ``CertRevocationError`` is
        raised, so the caller never ends up with two valid certificates.  The
        old artefact folder is kept for audit.

        Raises
        ------
        DBNotInitedError
            If no ``db_handler`` was provided.
        CertNotFound
            If no certificate with *serial* exists in the database.
        NotUniqueCertOwner
            If *config.common_name* belongs to a *different* VALID certificate.
        CertRevocationError
            If the old certificate could not be revoked.
        ValueError
            If ``self.factory`` has not been initialised.
        """
        self._require_db()
        self._require_factory()

        self._logger.info(
            "Rotating certificate: serial=%d, new_CN=%s", serial, config.common_name
        )

        existing = self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if not existing:
            self._logger.error("Certificate serial=%d not found for rotation", serial)
            raise CertNotFound()

        self._find_conflict(config.common_name, is_overwrite=False, exclude=serial)
        new_cert, new_key, new_csr = self._issue(
            config,
            file_name=self._derive_file_name(config),
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

    def renew_certificate(
        self,
        serial: int,
        days_valid: int = 365,
        valid_from: datetime | None = None,
        cert_path: str | None = None,
    ) -> x509.Certificate:
        """
        Renew the certificate identified by *serial*: same key, new validity.

        The renewed certificate is stored (``.pem`` only — the private key
        stays in the original folder, which is kept) and registered; the
        original is then revoked with reason ``superseded``.

        Raises
        ------
        DBNotInitedError
            If no ``db_handler`` was provided.
        CertNotFound
            If no record exists for *serial*.
        CertRevocationError
            If the original could not be revoked (the renewal is rolled back).
        ValueError
            If ``self.factory`` has not been initialised.
        """
        self._require_db()
        self._require_factory()

        record = self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if record is None:
            raise CertNotFound()

        cert_obj = x509.load_pem_x509_certificate(record.certificate_pem.encode())
        renewed = self._factory.renew_certificate(  # type: ignore[union-attr]
            cert=cert_obj, days_valid=days_valid, valid_from=valid_from
        )
        common_name = certificate_common_name(renewed)
        self._find_conflict(common_name, is_overwrite=False, exclude=serial)
        self._store_and_register(
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

    def inspect_certificate(self, cert: x509.Certificate) -> CertificateDetails:
        """Structured summary of *cert*. Delegates to the factory."""
        self._require_factory()
        return self._factory.inspect_certificate(cert)  # type: ignore[union-attr]

    def cosign_certificate(
        self,
        cert: x509.Certificate,
        days_valid: int | None = None,
        valid_from: datetime | None = None,
        serial_type: CertType | None = None,
        cert_path: str | None = None,
        is_overwrite: bool = False,
    ) -> x509.Certificate:
        """
        Re-sign *cert* with this CA, store the result and register it.

        Registration makes the co-signed certificate revocable and verifiable
        like any other certificate issued by this CA.

        Raises
        ------
        NotUniqueCertOwner
            If the CN already belongs to a VALID certificate and
            *is_overwrite* is ``False``.
        DBOperationError
            If registration fails.
        """
        self._require_factory()
        cosigned = self._factory.cosign_certificate(  # type: ignore[union-attr]
            cert=cert,
            days_valid=days_valid,
            valid_from=valid_from,
            serial_type=serial_type,
        )
        common_name = certificate_common_name(cosigned)
        replaced = self._find_conflict(common_name, is_overwrite)
        cert_type = SerialWithEncoding.parse(cosigned.serial_number)[0]
        self._store_and_register(
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

    def export_pkcs12(
        self,
        cert: x509.Certificate,
        private_key: PrivateKey,
        password: bytes | None = None,
        name: str | None = None,
    ) -> bytes:
        """Pack cert + key into a PKCS#12 bundle. Delegates to the factory."""
        self._require_factory()
        return self._factory.export_pkcs12(  # type: ignore[union-attr]
            cert=cert, private_key=private_key, password=password, name=name
        )

    def get_cert_chain(self, cert: x509.Certificate) -> list[x509.Certificate]:
        """Return the ``[cert, ca_cert]`` chain. Delegates to the factory."""
        self._require_factory()
        return self._factory.get_cert_chain(cert)  # type: ignore[union-attr]

    def issue_intermediate_ca(
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
        """
        Issue a subordinate CA signed by this CA, store it and register it.

        Certificate and key are saved together in one UUID folder as
        ``intermediate_ca.pem`` / ``intermediate_ca.key``.  Registration lets
        the intermediate be revoked through the root's CRL.

        Raises
        ------
        NotUniqueCertOwner
            If the CN is in use and *is_overwrite* is ``False``.
        """
        self._require_factory()
        replaced = self._find_conflict(common_name, is_overwrite)
        cert, key = self._factory.issue_intermediate_ca(  # type: ignore[union-attr]
            common_name=common_name,
            key_size=key_size,
            days_valid=days_valid,
            valid_from=valid_from,
            path_length=path_length,
            organization=organization,
            country=country,
            key_algorithm=key_algorithm,
        )
        self._store_and_register(
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

    def list_certificates(
        self,
        status: str | None = None,
        key_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CertificateRecord]:
        """Return paginated certificate records. Requires db_handler."""
        self._require_db()
        return self._db.list_all(  # type: ignore[union-attr]
            status=status, key_type=key_type, limit=limit, offset=offset
        )

    def get_expiring_soon(self, within_days: int = 30) -> list[CertificateRecord]:
        """Return VALID certs expiring within *within_days* days. Requires db_handler."""
        self._require_db()
        return self._db.get_expiring(within_days=within_days)  # type: ignore[union-attr]

    def delete_certificate(self, serial: int, cert_path: str | None = None) -> bool:
        """
        Hard-delete a certificate from the DB and its artefact folder from storage.

        Returns True if the DB row was deleted (storage deletion is best-effort).
        """
        self._require_db()
        record = self._db.get_by_serial(serial=serial)  # type: ignore[union-attr]
        if record is None:
            return False
        uuid = record.uuid
        deleted = self._db.delete_by_uuid(uuid=uuid)  # type: ignore[union-attr]
        if deleted and uuid:
            self._storage.delete_certificate_folder(uuid_str=uuid, cert_path=cert_path)
        return bool(deleted)

    def refresh_expired_statuses(self) -> int:
        """Bulk-mark expired certificates. Returns count of updated rows."""
        self._require_db()
        return self._db.update_status_expired()  # type: ignore[union-attr]

    def verify_crl(self, crl: x509.CertificateRevocationList) -> None:
        """Verify CRL signature and expiry. Delegates to the factory."""
        self._require_factory()
        self._factory.verify_crl(crl)  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _issue(
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
        certificate, private_key, csr = self._factory.issue_certificate(  # type: ignore[union-attr]
            **config.model_dump(exclude={"name"})
        )
        paths, _ = self._store_and_register(
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

    def _find_conflict(
        self,
        common_name: str,
        is_overwrite: bool,
        exclude: int | None = None,
    ) -> CertificateRecord | None:
        """
        Return the VALID record holding *common_name*, if it may be replaced.

        Raises ``NotUniqueCertOwner`` when such a record exists and
        *is_overwrite* is ``False``.  A record whose serial equals *exclude*
        is ignored (it is the certificate being rotated / renewed).  Without
        a database there is nothing to check.
        """
        if not self._db:
            return None
        existing = self._db.get_by_name(common_name=common_name)
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

    def _store_and_register(
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
        """
        Persist *artefacts*, register *certificate* and retire *replaced*.

        All-or-nothing from the caller's point of view: on any failure the
        written artefacts (and the new DB row) are removed and the error is
        re-raised.
        """
        paths: list[Path] = []
        effective_uuid = uuid_str
        try:
            for obj, name in artefacts:
                path, effective_uuid = self._storage.save_certificate(
                    cert=obj,
                    cert_path=cert_path,
                    file_name=name,
                    uuid_str=effective_uuid,
                    is_overwrite=is_overwrite,
                )
                paths.append(path)
            if self._db and not self._db.register_cert_in_db(
                cert=certificate, uuid=str(effective_uuid), key_type=cert_type
            ):
                raise DBOperationError(
                    "register_cert_in_db",
                    f"certificate serial={certificate.serial_number} was not stored",
                )
        except Exception:
            self._discard(paths, effective_uuid, uuid_str is None, cert_path)
            raise

        if replaced is not None and self._db:
            ok, status = self._db.revoke_certificate(
                serial_number=int(replaced.serial_number),
                reason=x509.ReasonFlags.superseded,
            )
            if not ok and status is not RevokeStatus.NOT_FOUND:
                self._db.delete_by_uuid(uuid=str(effective_uuid))
                self._discard(paths, effective_uuid, uuid_str is None, cert_path)
                raise CertRevocationError(
                    int(replaced.serial_number), getattr(status, "value", str(status))
                )
            if (
                delete_replaced_folder
                and replaced.uuid
                and str(replaced.uuid) != str(effective_uuid)
            ):
                self._storage.delete_certificate_folder(
                    uuid_str=str(replaced.uuid), cert_path=cert_path
                )

        if self._db:
            self._logger.debug(
                "Certificate registered in DB: serial=%s, uuid=%s",
                certificate.serial_number,
                effective_uuid,
            )
        return paths, effective_uuid

    def _discard(
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
                    self._storage.delete_certificate_folder(
                        uuid_str=uuid_str, cert_path=cert_path
                    )
            elif isinstance(self._storage, LocalStorage):
                for path in paths:
                    Path(path).unlink(missing_ok=True)
        except Exception as exc:  # pragma: no cover - best effort
            self._logger.error("Failed to clean up artefacts %s: %s", paths, exc)

    @staticmethod
    def _derive_file_name(config: ClientConfig) -> str:
        """
        Storage basename: ``config.name`` (validated by the model) or the CN
        made safe by :func:`safe_file_name`.
        """
        return config.name or safe_file_name(config.common_name)

    def _require_db(self) -> None:
        """Raise ``DBNotInitedError`` if no database handler is configured."""
        if not self._db:
            raise DBNotInitedError()

    def _require_factory(self) -> None:
        """Raise ``ValueError`` if no certificate factory is configured."""
        if not self._factory:
            raise ValueError(
                "factory is not initialised. "
                "Set CertLifecycleManager.factory before using this operation."
            )
