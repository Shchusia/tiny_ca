"""
CA material loading: Protocol definition and PEM-file-backed implementation.

This module provides two public symbols:

- ``ICALoader``    — a ``@runtime_checkable`` Protocol that defines the minimum
                     interface any CA-material provider must satisfy.  Consumers
                     (e.g. ``CertificateFactory``) depend only on this Protocol,
                     never on a concrete loader class (DIP).

- ``CAFileLoader`` — reads a CA certificate and private key from PEM files on
                     the local filesystem and exposes them through ``ICALoader``.
"""

from __future__ import annotations

import datetime
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
from tiny_ca.utils.keys import PRIVATE_KEY_TYPES, PrivateKey, PublicKey

_SPKI = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def certificate_info(cert: x509.Certificate) -> CertificateInfo:
    """Organisation / location attributes of *cert*'s Subject."""

    def _attr(oid: ObjectIdentifier) -> str | None:
        attrs = cert.subject.get_attributes_for_oid(oid)
        return cast(str, attrs[0].value) if attrs else None

    return CertificateInfo(
        organization=_attr(NameOID.ORGANIZATION_NAME),
        organizational_unit=_attr(NameOID.ORGANIZATIONAL_UNIT_NAME),
        country=_attr(NameOID.COUNTRY_NAME),
        state=_attr(NameOID.STATE_OR_PROVINCE_NAME),
        locality=_attr(NameOID.LOCALITY_NAME),
    )


def check_ca_material(
    ca_cert: x509.Certificate,
    public_key: PublicKey,
    cert_path: Path | str,
    key_path: Path | str,
    logger: Logger,
) -> None:
    """
    Verify that *ca_cert* and the CA key whose public half is *public_key*
    form a usable CA pair.

    Raises
    ------
    ErrorLoadCert
        If the key does not match the certificate, or the certificate is not
        a CA (``BasicConstraints.ca`` unset, or ``KeyUsage`` without
        ``keyCertSign``).
    """
    if public_key.public_bytes(*_SPKI) != ca_cert.public_key().public_bytes(*_SPKI):
        raise ErrorLoadCert(
            path_to_file=key_path,
            exc="private key does not match the CA certificate",
        )
    try:
        is_ca = ca_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        raise ErrorLoadCert(
            path_to_file=cert_path,
            exc="certificate is not a CA (BasicConstraints.ca is not set)",
        )
    try:
        usage = ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.key_cert_sign:
        raise ErrorLoadCert(
            path_to_file=cert_path,
            exc="certificate is not a CA (KeyUsage lacks keyCertSign)",
        )
    if ca_cert.not_valid_after_utc < datetime.datetime.now(datetime.UTC):
        logger.warning(
            "CA certificate %s expired at %s; it cannot issue or validate "
            "certificates",
            cert_path,
            ca_cert.not_valid_after_utc.isoformat(),
        )


# ---------------------------------------------------------------------------
# ISP / DIP: minimal interface for CA-material providers
# ---------------------------------------------------------------------------


@runtime_checkable
class ICALoader(Protocol):
    """
    Protocol that defines the minimum contract for CA-material providers.

    Any object that exposes the three properties below satisfies this Protocol
    and can be injected into ``CertificateFactory`` without any inheritance.
    This makes it trivial to substitute the real filesystem loader with an
    in-memory stub, an HSM-backed loader, or a mock in unit tests.

    Properties
    ----------
    ca_cert : x509.Certificate
        The loaded CA certificate object.
    ca_key : PrivateKey
        The loaded CA private key used for signing.
    base_info : CertificateInfo
        Structured metadata extracted from the CA certificate's Subject field
        (organization, country, state, locality, organizational unit).
    """

    @property
    def ca_cert(self) -> x509.Certificate: ...

    @property
    def ca_key(self) -> PrivateKey: ...

    @property
    def base_info(self) -> CertificateInfo: ...


# ---------------------------------------------------------------------------
# SRP: PEM-file-backed CA loader
# ---------------------------------------------------------------------------


class CAFileLoader:
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

    # ------------------------------------------------------------------
    # ICALoader properties
    # ------------------------------------------------------------------

    @property
    def ca_cert(self) -> x509.Certificate:
        """
        The deserialized CA certificate.

        Returns
        -------
        x509.Certificate
            The CA certificate loaded from *ca_cert_path*.
        """
        return self._ca_cert

    @property
    def ca_key(self) -> PrivateKey:
        """
        The deserialized CA private key.

        Returns
        -------
        PrivateKey
            The private key loaded from *ca_key_path*.
        """
        return self._ca_key

    @property
    def base_info(self) -> CertificateInfo:
        """
        Structured metadata extracted from the CA certificate Subject.

        Returns
        -------
        CertificateInfo
            Contains *organization*, *organizational_unit*, *country*,
            *state*, and *locality* fields; any absent attribute is ``None``.
        """
        return self._base_info

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        ca_cert_path: str | Path,
        ca_key_path: str | Path,
        ca_key_password: str | bytes | None = None,
        logger: Logger | None = None,
    ) -> None:
        self._logger = logger or DEFAULT_LOGGER

        self._ca_cert_path = self._validate_file(Path(ca_cert_path))
        self._ca_key_path = self._validate_file(Path(ca_key_path))

        # Normalise password to bytes so the cryptography library always
        # receives the expected type.
        password_bytes: bytes | None = None
        if ca_key_password is not None:
            password_bytes = (
                ca_key_password.encode("utf-8")
                if isinstance(ca_key_password, str)
                else ca_key_password
            )

        self._ca_cert, self._ca_key = self._load(password_bytes)
        self._base_info = self._extract_info()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_file(
        path: Path,
        allowed: tuple[str, ...] = ALLOWED_CERT_EXTENSIONS,
    ) -> Path:
        """
        Verify that *path* points to an existing regular file with a
        permitted extension.

        Parameters
        ----------
        path : Path
            Filesystem path to validate.
        allowed : tuple[str, ...]
            Whitelist of accepted file extensions (including the leading dot,
            e.g. ``".pem"``).  Defaults to ``ALLOWED_CERT_EXTENSIONS``.

        Returns
        -------
        Path
            The validated *path*, unchanged.

        Raises
        ------
        NotExistCertFile
            If *path* does not exist on the filesystem.
        IsNotFile
            If *path* exists but is a directory or other non-regular file.
        WrongType
            If the file extension is not listed in *allowed*.
        """
        if not path.exists():
            raise NotExistCertFile(path_to_file=path)
        if not path.is_file():
            raise IsNotFile(path_to_file=path)
        if path.suffix not in allowed:
            raise WrongType(wrong_type=path.suffix, allowed_types=allowed)
        return path

    def _load(
        self,
        password: bytes | None,
    ) -> tuple[x509.Certificate, PrivateKey]:
        """
        Read and deserialise the CA certificate and private key from PEM files.

        The certificate and key are loaded independently; a separate
        ``try/except`` block wraps each operation so that the failure message
        identifies exactly which file could not be read.

        Parameters
        ----------
        password : bytes | None
            Password for the private key, or ``None`` for unencrypted keys.

        Returns
        -------
        tuple[x509.Certificate, PrivateKey]
            ``(ca_cert, ca_key)`` ready for use.

        Raises
        ------
        ErrorLoadCert
            Wraps any underlying exception thrown during file I/O or PEM
            deserialisation, annotated with the offending file path.
        """
        try:
            with open(self._ca_cert_path, "rb") as fh:
                ca_cert = x509.load_pem_x509_certificate(fh.read(), default_backend())
        except Exception as exc:
            raise ErrorLoadCert(path_to_file=self._ca_cert_path, exc=str(exc)) from exc

        try:
            with open(self._ca_key_path, "rb") as fh:
                ca_key = serialization.load_pem_private_key(
                    fh.read(), password=password, backend=default_backend()
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
