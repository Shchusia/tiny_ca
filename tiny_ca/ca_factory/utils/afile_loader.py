from __future__ import annotations

import asyncio
from logging import Logger
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import serialization

from tiny_ca.const import ALLOWED_CERT_EXTENSIONS
from tiny_ca.exc import ErrorLoadCert, IsNotFile, NotExistCertFile, WrongType
from tiny_ca.models.certificate import CertificateInfo
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.utils.keys import PRIVATE_KEY_TYPES, PrivateKey

from .file_loader import CAFileLoader, certificate_info, check_ca_material


class AsyncCAFileLoader:
    """
    Loads a CA certificate and private key from PEM files on the local filesystem.

    Responsibility: file reading and PEM deserialisation *only*.
    Does not generate certificates, manage sessions, or perform any
    cryptographic operations beyond deserialisation.

    On construction the loader:
    1. Validates that both paths point to existing, regular files with
       permitted extensions (see ``ALLOWED_CERT_EXTENSIONS``).
    2. Deserialises the CA certificate and private key from PEM.
    3. Extracts ``CertificateInfo`` from the CA certificate's Subject.

    After successful construction all three ``ICALoader`` properties are
    available and will not change for the lifetime of the instance.

    Parameters
    ----------
    ca_cert_path : str | Path
        Path to the PEM-encoded CA certificate file.
    ca_key_path : str | Path
        Path to the PEM-encoded CA private key file.
    ca_key_password : str | bytes | None
        Optional password protecting the private key.  A ``str`` value is
        encoded to ``bytes`` using UTF-8 before being passed to the
        cryptography library.  ``None`` means the key is unencrypted.
    logger : Logger | None
        Logger instance for diagnostic messages.  Falls back to
        ``DEFAULT_LOGGER`` when ``None``.
    """

    def __init__(
        self,
        ca_cert_path: str | Path,
        ca_key_path: str | Path,
        ca_key_password: str | bytes | None = None,
        logger: Logger | None = None,
    ) -> None:
        self._logger = logger or DEFAULT_LOGGER
        self._ca_cert_path = CAFileLoader._validate_file(Path(ca_cert_path))
        self._ca_key_path = CAFileLoader._validate_file(Path(ca_key_path))

        self._password_bytes: bytes | None = None
        if ca_key_password is not None:
            self._password_bytes = (
                ca_key_password.encode("utf-8")
                if isinstance(ca_key_password, str)
                else ca_key_password
            )

        self._ca_cert: x509.Certificate | None = None
        self._ca_key: PrivateKey | None = None
        self._base_info: CertificateInfo | None = None

    @classmethod
    async def create(
        cls,
        ca_cert_path: str | Path,
        ca_key_path: str | Path,
        ca_key_password: str | bytes | None = None,
        logger: Logger | None = None,
    ) -> AsyncCAFileLoader:

        instance = cls(ca_cert_path, ca_key_path, ca_key_password, logger)
        await instance.load()
        return instance

    # ------------------------------------------------------------------
    # ICALoader properties
    # ------------------------------------------------------------------

    @property
    def ca_cert(self) -> x509.Certificate:
        if self._ca_cert is None:
            raise RuntimeError("Call 'await loader.load()' before accessing ca_cert.")
        return self._ca_cert

    @property
    def ca_key(self) -> PrivateKey:
        if self._ca_key is None:
            raise RuntimeError("Call 'await loader.load()' before accessing ca_key.")
        return self._ca_key

    @property
    def base_info(self) -> CertificateInfo:
        if self._base_info is None:
            raise RuntimeError("Call 'await loader.load()' before accessing base_info.")
        return self._base_info

    async def load(self) -> None:
        loop = asyncio.get_event_loop()
        ca_cert, ca_key = await loop.run_in_executor(
            None,
            self._load_sync,
        )
        self._ca_cert = ca_cert
        self._ca_key = ca_key
        self._base_info = self._extract_info()

    def _load_sync(self) -> tuple[x509.Certificate, PrivateKey]:

        try:
            with open(self._ca_cert_path, "rb") as fh:
                ca_cert = x509.load_pem_x509_certificate(fh.read(), default_backend())
        except Exception as exc:
            raise ErrorLoadCert(path_to_file=self._ca_cert_path, exc=str(exc)) from exc

        try:
            with open(self._ca_key_path, "rb") as fh:
                ca_key = serialization.load_pem_private_key(
                    fh.read(), password=self._password_bytes, backend=default_backend()
                )
        except Exception as exc:
            raise ErrorLoadCert(path_to_file=self._ca_key_path, exc=str(exc)) from exc

        self._logger.info("CA loaded successfully from %s", self._ca_cert_path)
        if not isinstance(ca_key, PRIVATE_KEY_TYPES):
            raise TypeError(
                "CA key must be RSA, ECDSA (P-256 / P-384) or Ed25519, "
                f"got {type(ca_key).__name__}"
            )
        check_ca_material(
            ca_cert,
            cast(PrivateKey, ca_key).public_key(),
            Path(self._ca_cert_path),
            Path(self._ca_key_path),
            self._logger,
        )
        return ca_cert, cast(PrivateKey, ca_key)

    def _extract_info(self) -> CertificateInfo:
        """Subject attributes of the loaded CA certificate."""
        return certificate_info(self._ca_cert)  # type: ignore[arg-type]
