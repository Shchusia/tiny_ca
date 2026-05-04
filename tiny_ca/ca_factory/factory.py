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

from collections.abc import AsyncGenerator, Generator
import datetime
import ipaddress
from logging import Logger
import os
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import Row

from ..const import CertType
from ..db.models import CertificateRecord
from ..exc import ValidationCertError
from ..models.certificate import CertificateDetails
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

    async def abuild_crl(
        self,
        revoked_certs: AsyncGenerator[Row[tuple[str, datetime.datetime, str]], None],
        days_valid: int = 1,
    ) -> x509.CertificateRevocationList:

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

        async for record in revoked_certs:
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(record[0]))
                .revocation_date(record[1])  # type: ignore
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
        crl = builder.sign(self._ca.ca_key, hashes.SHA256(), default_backend())
        self._logger.debug("CRL signed successfully")
        return crl

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
            except IndexError:  # pragma: no cover
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

    @staticmethod
    def inspect_certificate(cert: x509.Certificate) -> CertificateDetails:
        """
        Extract and return a structured, human-readable summary of *cert*.

        Parses every commonly-used X.509 v3 extension and Subject attribute
        into plain Python values wrapped in a :class:`CertificateDetails`
        dataclass.  The method never performs cryptographic verification —
        use :meth:`validate_cert` for that.  It is therefore safe to call on
        certificates from *any* issuer.

        Parameters
        ----------
        cert : x509.Certificate
            The certificate to inspect.  May have been issued by this CA or
            by a completely different PKI.

        Returns
        -------
        CertificateDetails
            A frozen dataclass with the following fields populated:

            - ``serial_number`` — raw integer serial.
            - ``common_name`` / ``organization`` / ``country`` — first
              matching Subject attribute, or ``None`` when absent.
            - ``issuer_cn`` — CN from the Issuer field, or ``None``.
            - ``not_valid_before`` / ``not_valid_after`` — UTC datetimes.
            - ``is_ca`` — ``True`` when ``BasicConstraints.ca`` is ``True``.
            - ``san_dns`` / ``san_ip`` — lists from the SAN extension.
            - ``key_usage`` — list of enabled ``KeyUsage`` bit names.
            - ``extended_key_usage`` — list of EKU OID dotted strings.
            - ``fingerprint_sha256`` — colon-separated uppercase hex.
            - ``subject_key_identifier`` — hex string or ``None``.
            - ``public_key_size`` — RSA key bits or ``None``.

        Examples
        --------
        >>> details = CertificateFactory.inspect_certificate(cert)
        >>> print(details.common_name)
        'nginx.internal'
        >>> print(details.is_ca)
        False
        >>> print(details.fingerprint_sha256[:8])
        'AB:CD:EF'
        """

        def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
            attrs = name.get_attributes_for_oid(oid)
            return cast(str, attrs[0].value) if attrs else None

        # ── Subject / Issuer ──────────────────────────────────────────
        common_name = _attr(cert.subject, NameOID.COMMON_NAME)
        organization = _attr(cert.subject, NameOID.ORGANIZATION_NAME)
        country = _attr(cert.subject, NameOID.COUNTRY_NAME)
        issuer_cn = _attr(cert.issuer, NameOID.COMMON_NAME)

        # ── BasicConstraints ─────────────────────────────────────────
        is_ca = False
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = bc.value.ca
        except x509.ExtensionNotFound:
            pass

        # ── SubjectAlternativeName ────────────────────────────────────
        san_dns: list[str] = []
        san_ip: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_dns = san_ext.value.get_values_for_type(x509.DNSName)
            san_ip = [
                str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)
            ]
        except x509.ExtensionNotFound:
            pass

        # ── KeyUsage ─────────────────────────────────────────────────
        _KU_BITS = (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
        )
        key_usage: list[str] = []
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            for bit in _KU_BITS:
                try:
                    if getattr(ku, bit):
                        key_usage.append(bit)
                except x509.exceptions.UnsupportedGeneralNameType:  # pragma: no cover
                    pass
        except x509.ExtensionNotFound:
            pass

        # ── ExtendedKeyUsage ─────────────────────────────────────────
        extended_key_usage: list[str] = []
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            extended_key_usage = [oid.dotted_string for oid in eku]
        except x509.ExtensionNotFound:
            pass

        # ── Fingerprint ───────────────────────────────────────────────
        raw_fp = cert.fingerprint(hashes.SHA256())
        fingerprint_sha256 = ":".join(f"{b:02X}" for b in raw_fp)

        # ── SubjectKeyIdentifier ──────────────────────────────────────
        subject_key_identifier: str | None = None
        try:
            ski = cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
            subject_key_identifier = ski.digest.hex()
        except x509.ExtensionNotFound:
            pass

        # ── Public key size ───────────────────────────────────────────
        public_key_size: int | None = None
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            public_key_size = pub.key_size

        return CertificateDetails(
            serial_number=cert.serial_number,
            common_name=common_name,
            organization=organization,
            country=country,
            issuer_cn=issuer_cn,
            not_valid_before=cert.not_valid_before_utc,
            not_valid_after=cert.not_valid_after_utc,
            is_ca=is_ca,
            san_dns=san_dns,
            san_ip=san_ip,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
            fingerprint_sha256=fingerprint_sha256,
            subject_key_identifier=subject_key_identifier,
            public_key_size=public_key_size,
        )

    # ------------------------------------------------------------------
    # Certificate co-signing
    # ------------------------------------------------------------------

    def export_pkcs12(
        self,
        cert: x509.Certificate,
        private_key: rsa.RSAPrivateKey,
        password: bytes | None = None,
        name: str | None = None,
    ) -> bytes:
        """
        Pack *cert* and *private_key* into a PKCS#12 (PFX) bundle.

        PKCS#12 is the standard container format accepted by Windows certificate
        stores, macOS Keychain, Java keystores, and most browser import dialogs.
        The CA certificate is automatically included as the issuer in the chain.

        Parameters
        ----------
        cert : x509.Certificate
            The leaf certificate to export.
        private_key : rsa.RSAPrivateKey
            The private key corresponding to *cert*'s public key.
        password : bytes | None
            Optional password to encrypt the PKCS#12 file.  ``None`` produces
            an unencrypted bundle (not recommended for production).
        name : str | None
            Friendly name (alias) embedded in the PKCS#12 bag.  Defaults to
            the certificate's Common Name when ``None``.

        Returns
        -------
        bytes
            Raw DER-encoded PKCS#12 bytes.  Write to a ``.p12`` or ``.pfx``
            file, or send as an HTTP response with
            ``Content-Type: application/x-pkcs12``.
        """
        if name is None:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            name = cast(str, cn_attrs[0].value) if cn_attrs else "certificate"

        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=name.encode(),
            key=private_key,
            cert=cert,
            cas=[self._ca.ca_cert],
            encryption_algorithm=encryption_algorithm,
        )
        self._logger.info("PKCS#12 exported: CN=%s", name)
        return p12_bytes

    def get_cert_chain(self, cert: x509.Certificate) -> list[x509.Certificate]:
        """
        Return the full certificate chain from *cert* up to the CA root.

        For a single-level PKI (leaf → root CA) this returns ``[cert, ca_cert]``.
        The list is ordered leaf-first, root-last — the same order expected by
        nginx ``ssl_certificate``, envoy ``tls_certificates``, and the
        ``fullchain.pem`` convention used by Let's Encrypt.

        Parameters
        ----------
        cert : x509.Certificate
            The leaf (or intermediate) certificate to start the chain from.

        Returns
        -------
        list[x509.Certificate]
            ``[cert, self._ca.ca_cert]`` — leaf first, CA root last.
        """
        self._logger.debug("Building cert chain for serial=%s", cert.serial_number)
        return [cert, self._ca.ca_cert]

    def renew_certificate(
        self,
        cert: x509.Certificate,
        days_valid: int = 365,
        valid_from: datetime.datetime | None = None,
    ) -> x509.Certificate:
        """
        Issue a renewal of *cert* with a fresh validity window but the same
        Subject, public key, and extensions.

        Unlike :meth:`rotate_certificate` (which generates a new key pair),
        renewal re-uses the existing public key.  This is appropriate when the
        private key has not been compromised and the owner simply needs to
        extend the validity period.

        The renewed certificate receives a new serial number generated by
        :class:`SerialWithEncoding` so it is distinguishable from the original
        in CRLs and audit logs.

        Parameters
        ----------
        cert : x509.Certificate
            The certificate to renew.  Its Subject, public key, and all v3
            extensions (except AKI, which is updated to point to the current CA)
            are copied verbatim into the renewal.
        days_valid : int
            Number of days the renewed certificate should be valid.
            Default: ``365``.
        valid_from : datetime.datetime | None
            Start of the new validity window.  ``None`` uses the current UTC
            time.

        Returns
        -------
        x509.Certificate
            A freshly signed certificate with the same identity but a new
            validity window and serial number.

        Raises
        ------
        InvalidRangeTimeCertificate
            If the computed expiry is already in the past.
        """
        not_before, not_after = CertLifetime.compute(valid_from, days_valid)

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn_raw = cast(str, cn_attrs[0].value) if cn_attrs else "renewed"
        cn_safe = cn_raw.lower().replace(os.sep, "_")
        new_serial = SerialWithEncoding.generate(
            name=cn_safe,
            serial_type=CertType.SERVICE,
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(cert.subject)
            .issuer_name(self._ca.ca_cert.subject)
            .public_key(cert.public_key())
            .serial_number(new_serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        _skip_oids = {x509.AuthorityKeyIdentifier.oid}
        for ext in cert.extensions:
            if ext.oid in _skip_oids:
                continue
            builder = builder.add_extension(ext.value, critical=ext.critical)

        try:
            ca_ski = self._ca.ca_cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
        except x509.ExtensionNotFound:  # pragma: no cover
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=None,
                    authority_cert_issuer=[
                        x509.DirectoryName(self._ca.ca_cert.subject)
                    ],
                    authority_cert_serial_number=self._ca.ca_cert.serial_number,
                ),
                critical=False,
            )

        renewed = builder.sign(self._ca.ca_key, hashes.SHA256(), default_backend())
        self._logger.info(
            "Certificate renewed: CN=%s, old_serial=%s → new_serial=%s, valid_until=%s",
            cn_raw,
            cert.serial_number,
            renewed.serial_number,
            not_after.isoformat(),
        )
        return renewed

    def issue_intermediate_ca(
        self,
        common_name: str,
        key_size: int = 4096,
        days_valid: int = 1825,
        valid_from: datetime.datetime | None = None,
        path_length: int | None = 0,
        organization: str | None = None,
        country: str | None = None,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Issue a subordinate (intermediate) CA certificate signed by this CA.

        The resulting certificate has ``BasicConstraints(ca=True)`` and
        ``KeyUsage(key_cert_sign=True, crl_sign=True)`` so it can in turn
        sign leaf certificates.  The ``path_length`` constraint limits how
        deep the sub-hierarchy can go.

        Parameters
        ----------
        common_name : str
            CN for the intermediate CA Subject.
        key_size : int
            RSA key size for the intermediate CA key.  Defaults to ``4096``
            (recommended for long-lived CA keys).
        days_valid : int
            Validity in calendar days.  Defaults to ``1825`` (5 years).
        valid_from : datetime.datetime | None
            Start of the validity window.  ``None`` uses the current UTC time.
        path_length : int | None
            ``BasicConstraints.path_length`` value.  ``0`` means this
            intermediate can only sign leaf certificates (cannot create further
            sub-CAs).  ``None`` means unlimited sub-levels.
        organization : str | None
            O field for the intermediate CA Subject.  Falls back to the parent
            CA's organization when ``None``.
        country : str | None
            C field.  Falls back to the parent CA's country when ``None``.

        Returns
        -------
        tuple[x509.Certificate, rsa.RSAPrivateKey]
            ``(intermediate_ca_cert, intermediate_ca_key)``.

        Raises
        ------
        InvalidRangeTimeCertificate
            If the computed expiry is already in the past.
        """
        self._logger.info(
            "Issuing intermediate CA: CN=%s, path_length=%s", common_name, path_length
        )

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )

        info = self._ca.base_info
        attrs: list[x509.NameAttribute] = []
        resolved_country = country or info.country
        resolved_org = organization or info.organization
        if resolved_country:  # pragma: no cover
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, resolved_country))
        if resolved_org:  # pragma: no cover
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, resolved_org))
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        subject = x509.Name(attrs)

        not_before, not_after = CertLifetime.compute(valid_from, days_valid)
        serial_number = SerialWithEncoding.generate(
            name=common_name.lower().replace(os.sep, "_"),
            serial_type=CertType.CA,
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca.ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=path_length),
                critical=True,
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
        )

        try:
            ca_ski = self._ca.ca_cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
        except x509.ExtensionNotFound:  # pragma: no cover
            pass

        cert = builder.sign(self._ca.ca_key, hashes.SHA256(), default_backend())
        self._logger.info(
            "Intermediate CA issued: CN=%s, serial=%s, valid_until=%s",
            common_name,
            cert.serial_number,
            not_after.isoformat(),
        )
        return cert, private_key

    def verify_crl(self, crl: x509.CertificateRevocationList) -> None:
        """
        Verify the signature and validity window of *crl*.

        Checks that:
        1. The CRL was signed by this CA's private key (issuer match + signature).
        2. The CRL's ``nextUpdate`` timestamp has not yet passed — i.e. the CRL
           is still within its declared validity window.

        Parameters
        ----------
        crl : x509.CertificateRevocationList
            The CRL object to verify.

        Returns
        -------
        None
            Returns silently when all checks pass.

        Raises
        ------
        ValidationCertError
            If the CRL issuer does not match this CA, the signature is invalid,
            or the CRL has expired (``nextUpdate`` is in the past).
        """
        if crl.issuer != self._ca.ca_cert.subject:
            raise ValidationCertError("CRL issuer does not match CA subject.")

        now = datetime.datetime.now(datetime.UTC)
        next_update = crl.next_update_utc
        if next_update is not None and next_update < now:
            raise ValidationCertError(
                f"CRL has expired: nextUpdate={next_update.isoformat()}, "
                f"now={now.isoformat()}"
            )

        try:
            crl.is_signature_valid(self._ca.ca_cert.public_key())  # type: ignore[arg-type]
        except Exception as exc:  # pragma: no cover
            raise ValidationCertError(
                f"CRL signature verification failed: {exc}"
            ) from exc

        self._logger.debug("CRL verified successfully")

    # ------------------------------------------------------------------
    # Certificate co-signing
    # ------------------------------------------------------------------

    def cosign_certificate(
        self,
        cert: x509.Certificate,
        days_valid: int | None = None,
        valid_from: datetime.datetime | None = None,
    ) -> x509.Certificate:
        """
        Re-sign an existing certificate with this CA's key and certificate.

        Creates a new ``x509.Certificate`` that preserves the original
        Subject, public key, and all v3 extensions, but replaces:

        - **Issuer** — set to this CA's Subject.
        - **AuthorityKeyIdentifier** — updated to reflect this CA's SKI.
        - **Serial number** — a fresh serial is generated so the co-signed
          certificate is distinguishable from the original in CRLs and logs.
        - **Validity window** — optionally overridden via *days_valid* and
          *valid_from*; when both are ``None`` the original window is
          preserved exactly.

        The certificate is signed with SHA-256 using ``self._ca.ca_key``.

        .. note::
            This operation does **not** verify that the original certificate
            was valid or trusted before co-signing.  Call
            :meth:`validate_cert` first if pre-validation is required.

        Parameters
        ----------
        cert : x509.Certificate
            The source certificate whose Subject, public key, and extensions
            are copied into the co-signed output.
        days_valid : int | None
            Override the validity duration in calendar days, counted from
            *valid_from* (or ``now`` when *valid_from* is also ``None``).
            ``None`` preserves the original ``not_valid_before`` /
            ``not_valid_after`` window unchanged.
        valid_from : datetime.datetime | None
            Override the start of the validity window.  Ignored when
            *days_valid* is ``None``.  ``None`` + *days_valid* set →
            uses the current UTC time as the start.

        Returns
        -------
        x509.Certificate
            A new certificate object identical in content to *cert* except
            for the issuer, AKI, serial number, and (optionally) validity
            window.  Must be persisted by the caller.

        Raises
        ------
        InvalidRangeTimeCertificate
            If *days_valid* is provided and the computed expiry is already
            in the past.

        Examples
        --------
        >>> cosigned = factory.cosign_certificate(third_party_cert, days_valid=365)
        >>> assert cosigned.issuer == factory._ca.ca_cert.subject
        >>> assert cosigned.subject == third_party_cert.subject
        """
        self._logger.info(
            "Co-signing certificate: CN=%s, original_serial=%s",
            (
                cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                else "<no CN>"
            ),
            cert.serial_number,
        )

        # ── Validity window ───────────────────────────────────────────
        if days_valid is not None:
            not_before, not_after = CertLifetime.compute(valid_from, days_valid)
        else:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

        # ── Fresh serial number ───────────────────────────────────────
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn_raw = cast(str, cn_attrs[0].value) if cn_attrs else "cosigned"
        cn_safe = cn_raw.lower().replace(os.sep, "_")
        new_serial = SerialWithEncoding.generate(
            name=cn_safe,
            serial_type=CertType.SERVICE,
        )

        # ── Rebuild extensions: copy originals, replace AKI ──────────
        builder = (
            x509.CertificateBuilder()
            .subject_name(cert.subject)
            .issuer_name(self._ca.ca_cert.subject)
            .public_key(cert.public_key())
            .serial_number(new_serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        # Copy every extension from the original certificate, but replace
        # AuthorityKeyIdentifier with one derived from *this* CA.
        _skip = {x509.AuthorityKeyIdentifier.oid}
        for ext in cert.extensions:
            if ext.oid in _skip:
                continue
            builder = builder.add_extension(ext.value, critical=ext.critical)

        # Always add a fresh AKI pointing at this CA.
        try:
            ca_ski = self._ca.ca_cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
        except x509.ExtensionNotFound:
            # CA has no SKI — fall back to issuer name + serial form.
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=None,
                    authority_cert_issuer=[
                        x509.DirectoryName(self._ca.ca_cert.subject)
                    ],
                    authority_cert_serial_number=self._ca.ca_cert.serial_number,
                ),
                critical=False,
            )

        cosigned = builder.sign(self._ca.ca_key, hashes.SHA256(), default_backend())

        self._logger.info(
            "Certificate co-signed: new_serial=%s, issuer=%s, valid_until=%s",
            cosigned.serial_number,
            self._ca.ca_cert.subject.rfc4514_string(),
            not_after.isoformat(),
        )
        return cosigned
