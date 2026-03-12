"""
factory.py

X.509 certificate factory: issues end-entity certificates, builds self-signed
CA certificates, generates CRLs, and validates certificate chains.

This module contains a single public class, ``CertificateFactory``, whose only
responsibility is cryptographic construction.  It never touches the filesystem,
the database, or any business-logic layer.

SOLID notes
-----------
SRP : ``CertificateFactory`` handles cryptographic generation only.
      File persistence → ``BaseStorage``.  DB registration → ``BaseDB``.
OCP : New X.509 extension types are added in ``_build_extensions`` without
      modifying any other method.
LSP : Any ``ICALoader`` implementation can be swapped in transparently.
ISP : ``SerialWithEncoding`` and ``CertLifetime`` are separate utility modules;
      only the symbols needed here are imported.
DIP : CA material is provided through the ``ICALoader`` Protocol injected at
      construction time; the factory never instantiates a loader itself.
"""

from __future__ import annotations

from collections.abc import Generator
import datetime
import ipaddress
from logging import Logger
import os
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ..const import CertType
from ..db.models import CertificateRecord
from ..exc import ValidationCertError
from ..settings import DEFAULT_LOGGER
from ..utils.serial_generator import SerialWithEncoding
from .utils import CertLifetime, ICALoader


class CertificateFactory:
    """
    Cryptographic factory for X.509 certificates, CSRs, and CRLs.

    ``CertificateFactory`` is the single source of all certificate-generation
    logic in the library.  It accepts an ``ICALoader`` at construction time and
    uses the CA certificate and key it provides to sign all issued artefacts.

    Responsibilities
    ----------------
    - Generate self-signed root CA certificates (``build_self_signed_ca``).
    - Issue end-entity certificates signed by the loaded CA (``issue_certificate``).
    - Build and sign Certificate Revocation Lists (``build_crl``).
    - Validate an existing certificate against the loaded CA (``validate_cert``).

    Out of scope
    ------------
    - Writing any files to disk.
    - Recording certificates in a database.
    - Business-level rules (duplicate CN detection, rotation policies, etc.).

    Parameters
    ----------
    ca_loader : ICALoader
        Provider of the CA certificate, private key, and base Subject info.
        Must satisfy the ``ICALoader`` Protocol (see ``file_loader.py``).
    logger : Logger | None
        Logger for operational messages.  Falls back to ``DEFAULT_LOGGER``
        when ``None``.

    Raises
    ------
    TypeError
        If *ca_loader* does not implement the ``ICALoader`` Protocol.
    """

    def __init__(
        self,
        ca_loader: ICALoader,
        logger: Logger | None = None,
    ) -> None:
        if not isinstance(ca_loader, ICALoader):
            raise TypeError(
                f"ca_loader must implement ICALoader, got {type(ca_loader)}"
            )
        self._ca = ca_loader
        self._logger = logger or DEFAULT_LOGGER

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def build_self_signed_ca(
        common_name: str = "Internal CA",
        organization: str = "My Company",
        country: str = "UA",
        key_size: int = 2048,
        days_valid: int = 3650,
        valid_from: datetime.datetime | None = None,
        logger: Logger | None = None,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Generate a self-signed root CA certificate and its private key.

        This is a ``@staticmethod`` — it requires no loaded CA because the
        resulting certificate is its own issuer.  It is typically called once
        during bootstrap to establish the trust anchor for the PKI.

        The generated certificate includes:
        - ``BasicConstraints(ca=True)`` — marks it as a CA certificate.
        - ``KeyUsage`` with ``key_cert_sign`` and ``crl_sign`` set to ``True``.
        - ``SubjectKeyIdentifier`` derived from the public key.

        Parameters
        ----------
        common_name : str
            Common Name (CN) for the CA Subject / Issuer fields.
            Default: ``"Internal CA"``.
        organization : str
            Organization (O) field.  Default: ``"My Company"``.
        country : str
            Two-letter ISO 3166-1 alpha-2 country code (C field).
            Default: ``"UA"``.
        key_size : int
            RSA key length in bits.  Use ``2048`` for standard security or
            ``4096`` for long-lived roots.  Default: ``2048``.
        days_valid : int
            Validity period in calendar days.  Default: ``3650`` (≈10 years).
        valid_from : datetime.datetime | None
            Start of the validity period.  ``None`` uses the current UTC time.
        logger : Logger | None
            Optional logger.  Falls back to ``DEFAULT_LOGGER``.

        Returns
        -------
        tuple[x509.Certificate, rsa.RSAPrivateKey]
            ``(certificate, private_key)`` — both must be persisted by the caller.

        Raises
        ------
        InvalidRangeTimeCertificate
            If the computed expiry date is already in the past.
        """
        _log = logger or DEFAULT_LOGGER
        _log.info(
            "Generating CA certificate: CN=%s, key_size=%d", common_name, key_size
        )

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
        valid_from_dt, valid_to_dt = CertLifetime.compute(valid_from, days_valid)
        serial_number = SerialWithEncoding.generate(
            name=common_name.lower().replace(os.sep, "_"),
            serial_type=CertType.CA,
        )

        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(serial_number)
            .not_valid_before(valid_from_dt)
            .not_valid_after(valid_to_dt)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )

        _log.info(
            "CA certificate created: subject=%s, valid_until=%s",
            subject.rfc4514_string(),
            valid_to_dt.isoformat(),
        )
        return certificate, private_key

    def issue_certificate(
        self,
        common_name: str,
        serial_type: CertType = CertType.SERVICE,
        key_size: int = 2048,
        days_valid: int = 365,
        valid_from: datetime.datetime | None = None,
        email: str | None = None,
        is_server_cert: bool = False,
        is_client_cert: bool = False,
        san_dns: list[str] | None = None,
        san_ip: list[str] | None = None,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey, x509.CertificateSigningRequest]:
        """
        Issue a signed end-entity certificate for the given subject parameters.

        Workflow:
        1. Generate a fresh RSA key pair.
        2. Build the Subject ``x509.Name`` from CA base info + *common_name* / *email*.
        3. Create a CSR signed with the new private key.
        4. Assemble X.509 extensions (KeyUsage, EKU, SAN, SKI, AKI).
        5. Sign the certificate with the CA key from ``self._ca``.

        The Subject inherits *country* and *organization* from the CA's own
        certificate so that all issued certificates share a consistent issuer
        hierarchy.

        Parameters
        ----------
        common_name : str
            Common Name (CN) for the new certificate's Subject.
        serial_type : CertType
            Certificate category used when encoding the serial number.
            Default: ``CertType.SERVICE``.
        key_size : int
            RSA key length in bits.  Default: ``2048``.
        days_valid : int
            Validity period in calendar days.  Default: ``365``.
        valid_from : datetime.datetime | None
            Start of the validity period.  ``None`` uses the current UTC time.
        email : str | None
            Optional email address added as an ``emailAddress`` Subject attribute.
        is_server_cert : bool
            When ``True``, adds ``ServerAuth`` to the Extended Key Usage
            extension and includes *common_name* as a DNS SAN (RFC 2818
            compliance).
        is_client_cert : bool
            When ``True``, adds ``ClientAuth`` to the Extended Key Usage
            extension.
        san_dns : list[str] | None
            Additional DNS names for the Subject Alternative Name extension.
        san_ip : list[str] | None
            IP addresses (as strings) for the Subject Alternative Name extension.

        Returns
        -------
        tuple[x509.Certificate, rsa.RSAPrivateKey, x509.CertificateSigningRequest]
            ``(certificate, private_key, csr)`` — the certificate and key must
            be persisted by the caller; the CSR is returned for audit purposes.

        Raises
        ------
        InvalidRangeTimeCertificate
            If the computed expiry date is already in the past.
        """
        self._logger.info(
            "Issuing certificate: CN=%s, type=%s, server=%s, client=%s",
            common_name,
            serial_type,
            is_server_cert,
            is_client_cert,
        )

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )

        subject = self._build_subject(common_name, email)
        csr = self._build_csr(subject, private_key)
        extensions = self._build_extensions(
            csr, is_server_cert, is_client_cert, san_dns, san_ip
        )

        valid_from_dt, valid_to_dt = CertLifetime.compute(valid_from, days_valid)
        serial_number = SerialWithEncoding.generate(
            name=common_name.lower().replace(os.sep, "_"),
            serial_type=serial_type,
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca.ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial_number)
            .not_valid_before(valid_from_dt)
            .not_valid_after(valid_to_dt)
        )
        for ext, critical in extensions:
            builder = builder.add_extension(ext, critical=critical)

        certificate = builder.sign(self._ca.ca_key, hashes.SHA256(), default_backend())

        self._logger.info(
            "Certificate issued: CN=%s, serial=%s, valid_until=%s",
            common_name,
            certificate.serial_number,
            valid_to_dt.isoformat(),
        )
        return certificate, private_key, csr

    def build_crl(
        self,
        revoked_certs: Generator[CertificateRecord, None, None],
        days_valid: int = 1,
    ) -> x509.CertificateRevocationList:
        """
        Build and sign a Certificate Revocation List from the provided records.

        Iterates over *revoked_certs*, adds each entry to the CRL builder, then
        signs the list with the CA private key.  The resulting CRL is valid from
        the current UTC time until ``now + days_valid`` days.

        Parameters
        ----------
        revoked_certs : Generator[CertificateRecord, None, None]
            Iterable of revoked certificate records as returned by
            ``BaseDB.get_revoked_certificates``.  Each record must expose
            ``serial_number`` (castable to ``int``) and ``revocation_date``
            (a ``datetime`` object).
        days_valid : int
            Number of days until the CRL expires and must be regenerated.
            Typical values are ``1`` (daily rotation) to ``7`` (weekly).
            Default: ``1``.

        Returns
        -------
        x509.CertificateRevocationList
            The signed CRL object.  The caller is responsible for persisting it
            to storage via ``BaseStorage``.
        """
        now = datetime.datetime.now(datetime.UTC)
        self._logger.info(
            "Building CRL: valid until %s",
            (now + datetime.timedelta(days=days_valid)).isoformat(),
        )

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._ca.ca_cert.subject)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=days_valid))
        )
        for record in revoked_certs:
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(record.serial_number))
                .revocation_date(record.revocation_date)  # type: ignore
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)

        crl = builder.sign(self._ca.ca_key, hashes.SHA256(), default_backend())
        self._logger.debug("CRL signed successfully")
        return crl

    async abuild_ccrl

    def validate_cert(self, cert: x509.Certificate) -> None:
        """
        Verify that *cert* was issued by this CA, is within its validity window,
        and carries a cryptographically correct signature.

        Three checks are performed in order:
        1. **Issuer match** — ``cert.issuer`` must equal the CA's Subject.
        2. **Validity window** — current UTC time must be between
           ``cert.not_valid_before_utc`` and ``cert.not_valid_after_utc``.
        3. **Signature** — the CA public key is used to verify the certificate
           signature using PKCS#1 v1.5 with the algorithm declared in the cert.

        Parameters
        ----------
        cert : x509.Certificate
            The certificate to validate.

        Returns
        -------
        None
            Returns silently when all checks pass.

        Raises
        ------
        ValidationCertError
            If any of the three checks fails.  The message describes which
            check failed and includes the relevant values (timestamps, issuer).
        """
        self._logger.debug("Validating certificate serial=%s", cert.serial_number)

        if cert.issuer != self._ca.ca_cert.subject:
            raise ValidationCertError(
                "Certificate issuer does not match the CA subject."
            )

        now = datetime.datetime.now(datetime.UTC)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if not_before > now or not_after < now:
            raise ValidationCertError(
                f"Certificate is outside its validity window: "
                f"not_before={not_before.isoformat()}, "
                f"not_after={not_after.isoformat()}, "
                f"now={now.isoformat()}"
            )

        try:
            self._ca.ca_cert.public_key().verify(  # type: ignore
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),  # type: ignore
                cert.signature_hash_algorithm,
            )
        except Exception as exc:
            raise ValidationCertError(f"Signature verification failed: {exc}") from exc

        self._logger.debug(
            "Certificate serial=%s passed all validation checks", cert.serial_number
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_subject(self, common_name: str, email: str | None) -> x509.Name:
        """
        Construct the Subject ``x509.Name`` for a new end-entity certificate.

        Attributes are populated in the following order (absent CA attributes
        are skipped):
        1. Country (C) — inherited from the CA's base info.
        2. Organization (O) — inherited from the CA's base info.
        3. Common Name (CN) — always present, taken from *common_name*.
        4. Email Address — only if *email* is not ``None``.

        Parameters
        ----------
        common_name : str
            CN value for the new certificate's Subject.
        email : str | None
            Optional email address to include as an ``emailAddress`` attribute.

        Returns
        -------
        x509.Name
            Fully constructed Subject name ready for use in a certificate builder.
        """
        attrs: list[x509.NameAttribute[Any]] = []
        info = self._ca.base_info

        if info.country:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, info.country))
        if info.organization:
            attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, info.organization)
            )

        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

        if email:
            attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        return x509.Name(attrs)

    @staticmethod
    def _build_csr(
        subject: x509.Name,
        private_key: rsa.RSAPrivateKey,
    ) -> x509.CertificateSigningRequest:
        """
        Create a Certificate Signing Request for *subject* signed with *private_key*.

        The CSR is self-signed (the applicant proves possession of the private
        key) using SHA-256.  It carries no extensions — extensions are added to
        the final certificate by the CA, not the CSR.

        Parameters
        ----------
        subject : x509.Name
            The Subject name to embed in the CSR.
        private_key : rsa.RSAPrivateKey
            The private key corresponding to the public key that will appear
            in the issued certificate.

        Returns
        -------
        x509.CertificateSigningRequest
            The signed CSR, retained for audit purposes and passed to the
            certificate builder to copy the public key.
        """
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )

    def _build_extensions(
        self,
        csr: x509.CertificateSigningRequest,
        is_server_cert: bool,
        is_client_cert: bool,
        san_dns: list[str] | None,
        san_ip: list[str] | None,
    ) -> list[tuple[x509.ExtensionType, bool]]:
        """
        Assemble the list of X.509 v3 extensions for a new end-entity certificate.

        Always-present extensions
        ~~~~~~~~~~~~~~~~~~~~~~~~~
        - ``BasicConstraints(ca=False)`` — critical; marks this as a leaf cert.
        - ``KeyUsage(digital_signature=True, key_encipherment=True)`` — critical.

        Conditionally-added extensions
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        - ``ExtendedKeyUsage`` — added when at least one of *is_server_cert*
          or *is_client_cert* is ``True``; contains ``ServerAuth`` and/or
          ``ClientAuth`` OIDs accordingly.
        - ``SubjectAlternativeName`` — added when any SAN entries exist.
          When *is_server_cert* is ``True`` the CN is automatically prepended
          as a DNS SAN for RFC 2818 compliance.  Additional DNS names and IP
          addresses from *san_dns* / *san_ip* are appended.
        - ``SubjectKeyIdentifier`` — always added; derived from the CSR public key.
        - ``AuthorityKeyIdentifier`` — always added; derived from the CA's own
          ``SubjectKeyIdentifier`` extension.

        Parameters
        ----------
        csr : x509.CertificateSigningRequest
            The CSR whose public key is used to derive ``SubjectKeyIdentifier``.
        is_server_cert : bool
            Include ``ServerAuth`` EKU and add CN as a DNS SAN.
        is_client_cert : bool
            Include ``ClientAuth`` EKU.
        san_dns : list[str] | None
            Extra DNS names for the SAN extension.
        san_ip : list[str] | None
            IP address strings (e.g. ``"192.168.1.1"``) for the SAN extension.

        Returns
        -------
        list[tuple[x509.ExtensionType, bool]]
            Ordered list of ``(extension_object, is_critical)`` pairs ready to
            be passed to ``CertificateBuilder.add_extension``.
        """
        result: list[tuple[x509.ExtensionType, bool]] = [
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            ),
        ]

        # Extended Key Usage — only added when at least one usage flag is set.
        eku: list[x509.ObjectIdentifier] = []
        if is_server_cert:
            eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if is_client_cert:
            eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        if eku:
            result.append((x509.ExtendedKeyUsage(eku), False))

        # Subject Alternative Names.
        # For server certificates the CN is included per RFC 2818 §3.1 which
        # requires modern TLS clients to check SANs rather than the CN.
        san: list[x509.GeneralName] = []
        if is_server_cert:
            try:
                cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                san.append(
                    x509.DNSName(cn if isinstance(cn, str) else cn.decode("utf-8"))
                )
            except IndexError:
                pass
        if san_dns:
            san.extend(x509.DNSName(d) for d in san_dns)
        if san_ip:
            san.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ip)
        if san:
            result.append((x509.SubjectAlternativeName(san), is_server_cert))

        # Key identifiers — required by RFC 5280 §4.2.1.2 and §4.2.1.1.
        result.append(
            (x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), False)
        )
        result.append(
            (
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    self._ca.ca_cert.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier
                    ).value
                ),
                False,
            )
        )

        return result
