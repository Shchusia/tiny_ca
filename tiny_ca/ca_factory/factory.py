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

from collections.abc import AsyncIterable, Iterable, Sequence
import datetime
import ipaddress
from logging import Logger
import os
import time
from typing import Any, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
)

from ..const import (
    DEFAULT_KEY_ALGORITHM,
    DEFAULT_LEAF_DAYS_VALID,
    DEFAULT_RSA_KEY_SIZE,
    CertType,
    KeyAlgorithm,
)
from ..exc import InvalidRangeTimeCertificate, ValidationCertError
from ..models.certificate import CertificateDetails, NameConstraintsConfig
from ..settings import DEFAULT_LOGGER
from ..signing import CASigner, KeySigner, sign_builder
from ..utils.keys import (
    PUBLIC_KEY_TYPES,
    PrivateKey,
    PublicKey,
    generate_private_key,
    public_key_info,
    signing_hash,
)
from ..utils.serial_generator import SerialWithEncoding
from .utils import CertLifetime, ICALoader, ISignerCALoader
from .utils.name_constraints import (
    build_name_constraints,
    check_certificate,
    check_name_constraints,
    issuer_name_constraints,
)

#: Extensions that describe *where the issuer publishes things*.  They are
#: dropped when a certificate is re-signed (renew / co-sign) so that stale
#: pointers to another CA's CRL / AIA never survive.
_ISSUER_BOUND_EXTENSIONS = frozenset(
    {
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        ExtensionOID.CRL_DISTRIBUTION_POINTS,
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
    }
)

#: Maximum number of certificates walked by :meth:`validate_chain`.
_MAX_CHAIN_DEPTH = 10


def _first_cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8")


def _record_field(record: Any, name: str, index: int) -> Any:
    """Read *name* from an ORM record / SQLAlchemy Row, or *index* from a tuple."""
    try:
        return getattr(record, name)
    except AttributeError:
        return record[index]


def _parse_reason(value: object) -> x509.ReasonFlags | None:
    """
    Convert a stored revocation reason into ``x509.ReasonFlags``.

    Accepts a ``ReasonFlags`` member or its string value (``"keyCompromise"``).
    Unknown values and ``unspecified`` return ``None`` — RFC 5280 §5.3.1 says
    the ``unspecified`` reason code SHOULD be omitted from CRL entries.
    """
    if value is None:
        return None
    try:
        reason = (
            value if isinstance(value, x509.ReasonFlags) else x509.ReasonFlags(value)
        )
    except ValueError:
        return None
    if reason in (x509.ReasonFlags.unspecified, x509.ReasonFlags.remove_from_crl):
        return None
    return reason


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
    - Issue subordinate CA certificates (``issue_intermediate_ca``).
    - Build and sign Certificate Revocation Lists (``build_crl``).
    - Validate certificates directly (``validate_cert``) or through
      intermediates (``validate_chain``).

    Out of scope
    ------------
    - Writing any files to disk.
    - Recording certificates in a database.
    - Business-level rules (duplicate CN detection, rotation policies, etc.).

    Parameters
    ----------
    ca_loader : ICALoader | ISignerCALoader
        Provider of the CA certificate, base Subject info and either the CA
        private key (``ICALoader``, e.g. ``CAFileLoader``) or an external
        signer (``ISignerCALoader``, e.g. ``SignerCALoader`` backed by an
        HSM).  RSA, ECDSA (P-256 / P-384) and Ed25519 CA keys are supported.
    logger : Logger | None
        Logger for operational messages.  Falls back to ``DEFAULT_LOGGER``.
    crl_distribution_points : Sequence[str] | None
        URLs where this CA publishes its CRL (e.g.
        ``["http://pki.example/crl.pem"]``).  When set, every issued
        certificate gets a ``CRLDistributionPoints`` extension so relying
        parties can find the CRL.
    ca_issuers_urls : Sequence[str] | None
        URLs where the CA certificate can be downloaded; added as
        ``caIssuers`` entries of ``AuthorityInformationAccess``.
    ocsp_urls : Sequence[str] | None
        OCSP responder URLs; added as ``OCSP`` entries of
        ``AuthorityInformationAccess``.
    certificate_policies : Sequence[str]
        Dotted policy OIDs (e.g. your organisation's certificate policy)
        written as a ``CertificatePolicies`` extension into every
        certificate this CA issues, renews or co-signs.
    cps_uri : str | None
        URI of the Certification Practice Statement, attached as a CPS
        qualifier to every policy.  Requires *certificate_policies*.

    Raises
    ------
    TypeError
        If *ca_loader* implements neither ``ICALoader`` nor ``ISignerCALoader``.
    ValueError
        If a policy OID is malformed or *cps_uri* is given without policies.
    """

    def __init__(
        self,
        ca_loader: ICALoader | ISignerCALoader,
        logger: Logger | None = None,
        crl_distribution_points: Sequence[str] | None = None,
        ca_issuers_urls: Sequence[str] | None = None,
        ocsp_urls: Sequence[str] | None = None,
        certificate_policies: Sequence[str] = (),
        cps_uri: str | None = None,
    ) -> None:
        if not isinstance(ca_loader, ISignerCALoader | ICALoader):
            raise TypeError(
                "ca_loader must implement ICALoader or ISignerCALoader, "
                f"got {type(ca_loader)}"
            )
        self._ca = ca_loader
        self._logger = logger or DEFAULT_LOGGER
        self._crl_urls = list(crl_distribution_points or [])
        self._ca_issuers_urls = list(ca_issuers_urls or [])
        self._ocsp_urls = list(ocsp_urls or [])
        self._policies = self._build_policies(certificate_policies, cps_uri)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def build_self_signed_ca(
        common_name: str = "Internal CA",
        organization: str = "My Company",
        country: str = "UA",
        key_size: int = DEFAULT_RSA_KEY_SIZE,
        days_valid: int = 3650,
        valid_from: datetime.datetime | None = None,
        logger: Logger | None = None,
        key_algorithm: KeyAlgorithm = DEFAULT_KEY_ALGORITHM,
    ) -> tuple[x509.Certificate, PrivateKey]:
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
        organization : str
            Organization (O) field.
        country : str
            Two-letter ISO 3166-1 alpha-2 country code (C field).
        key_size : int
            RSA key length in bits (ignored for EC / Ed25519).
        days_valid : int
            Validity period in calendar days.  Default: ``3650`` (≈10 years).
        valid_from : datetime.datetime | None
            Start of the validity period.  ``None`` uses the current UTC time.
        logger : Logger | None
            Optional logger.  Falls back to ``DEFAULT_LOGGER``.
        key_algorithm : KeyAlgorithm
            Algorithm of the CA key pair.  Default: RSA.

        Returns
        -------
        tuple[x509.Certificate, PrivateKey]
            ``(certificate, private_key)`` — both must be persisted by the caller.

        Raises
        ------
        InvalidRangeTimeCertificate
            If the computed expiry date is already in the past.
        """
        _log = logger or DEFAULT_LOGGER
        _log.info(
            "Generating CA certificate: CN=%s, algorithm=%s, key_size=%d",
            common_name,
            key_algorithm.value,
            key_size,
        )

        private_key = generate_private_key(key_algorithm, key_size)
        certificate = CertificateFactory._self_signed(
            KeySigner(private_key),
            common_name,
            organization,
            country,
            days_valid,
            valid_from,
            _log,
        )
        return certificate, private_key

    @staticmethod
    def build_self_signed_ca_with_signer(
        signer: CASigner,
        common_name: str = "Internal CA",
        organization: str = "My Company",
        country: str = "UA",
        days_valid: int = 3650,
        valid_from: datetime.datetime | None = None,
        logger: Logger | None = None,
    ) -> x509.Certificate:
        """
        Build a self-signed root CA certificate for a key held by *signer*.

        Use this when the CA key pair was generated inside an HSM (e.g. with
        ``pkcs11-tool --keypairgen``) and must never leave it: wrap the token
        key in a :class:`~tiny_ca.signing.Pkcs11Signer` (its ``public_key``
        taken from the token) and pass it here.  The resulting certificate
        has the same extensions as :meth:`build_self_signed_ca`; load it
        with ``SignerCALoader(cert, signer)`` to operate the CA.

        Raises
        ------
        InvalidRangeTimeCertificate
            If the computed expiry date is already in the past.
        SignerError
            If the signer fails or returns an invalid signature.
        """
        return CertificateFactory._self_signed(
            signer,
            common_name,
            organization,
            country,
            days_valid,
            valid_from,
            logger or DEFAULT_LOGGER,
        )

    @staticmethod
    def _self_signed(
        signer: CASigner,
        common_name: str,
        organization: str,
        country: str,
        days_valid: int,
        valid_from: datetime.datetime | None,
        log: Logger,
    ) -> x509.Certificate:
        public_key = signer.public_key()
        subject = x509.Name(
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
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(valid_from_dt)
            .not_valid_after(valid_to_dt)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(CertificateFactory._ca_key_usage(), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
        )
        certificate = cast(x509.Certificate, sign_builder(builder, signer))
        log.info(
            "CA certificate created: subject=%s, valid_until=%s",
            subject.rfc4514_string(),
            valid_to_dt.isoformat(),
        )
        return certificate

    def issue_certificate(
        self,
        common_name: str,
        serial_type: CertType = CertType.SERVICE,
        key_size: int = DEFAULT_RSA_KEY_SIZE,
        days_valid: int = DEFAULT_LEAF_DAYS_VALID,
        valid_from: datetime.datetime | None = None,
        email: str | None = None,
        is_server_cert: bool = False,
        is_client_cert: bool = False,
        san_dns: list[str] | None = None,
        san_ip: list[Any] | None = None,
        key_algorithm: KeyAlgorithm = DEFAULT_KEY_ALGORITHM,
    ) -> tuple[x509.Certificate, PrivateKey, x509.CertificateSigningRequest]:
        """
        Issue a signed end-entity certificate for the given subject parameters.

        Workflow:
        1. Generate a fresh key pair (*key_algorithm*).
        2. Build the Subject ``x509.Name`` from CA base info + *common_name* / *email*.
        3. Create a CSR signed with the new private key.
        4. Assemble X.509 extensions (KeyUsage, EKU, SAN, SKI, AKI and — when
           configured — CRLDistributionPoints / AuthorityInformationAccess).
        5. Sign the certificate with the CA key from ``self._ca``.

        Parameters
        ----------
        common_name : str
            Common Name (CN) for the new certificate's Subject.
        serial_type : CertType
            Certificate category used when encoding the serial number.
        key_size : int
            RSA key length in bits (ignored for EC / Ed25519).
        days_valid : int
            Validity period in calendar days.  Default: ``365``.
        valid_from : datetime.datetime | None
            Start of the validity period.  ``None`` uses the current UTC time.
        email : str | None
            Optional email address added as an ``emailAddress`` Subject attribute.
        is_server_cert : bool
            Adds ``ServerAuth`` EKU and includes *common_name* as a DNS SAN.
        is_client_cert : bool
            Adds ``ClientAuth`` EKU.
        san_dns : list[str] | None
            Additional DNS names for the Subject Alternative Name extension.
        san_ip : list[str | IPv4Address | IPv6Address] | None
            IP addresses for the Subject Alternative Name extension.
        key_algorithm : KeyAlgorithm
            Algorithm of the new key pair.  Default: RSA.

        Returns
        -------
        tuple[x509.Certificate, PrivateKey, x509.CertificateSigningRequest]
            ``(certificate, private_key, csr)``.

        Raises
        ------
        InvalidRangeTimeCertificate
            If the computed expiry date is already in the past.
        NameConstraintViolation
            If the subject e-mail or a SAN violates the CA's NameConstraints.
        """
        self._logger.info(
            "Issuing certificate: CN=%s, type=%s, algorithm=%s, server=%s, client=%s",
            common_name,
            serial_type,
            key_algorithm.value,
            is_server_cert,
            is_client_cert,
        )

        private_key = generate_private_key(key_algorithm, key_size)

        subject = self._build_subject(common_name, email)
        csr = self._build_csr(subject, private_key)
        extensions = self._build_extensions(
            csr, is_server_cert, is_client_cert, san_dns, san_ip
        )
        self._check_own_name_constraints(
            subject,
            next(
                (
                    e
                    for e, _ in extensions
                    if isinstance(e, x509.SubjectAlternativeName)
                ),
                None,
            ),
        )

        valid_from_dt, valid_to_dt = CertLifetime.compute(valid_from, days_valid)
        valid_to_dt = self._fit_ca_lifetime(valid_from_dt, valid_to_dt)
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

        certificate: x509.Certificate = self._sign(builder)

        self._logger.info(
            "Certificate issued: CN=%s, serial=%s, valid_until=%s",
            common_name,
            certificate.serial_number,
            valid_to_dt.isoformat(),
        )
        return certificate, private_key, csr

    def build_crl(
        self,
        revoked_certs: Iterable[Any],
        days_valid: int = 1,
        crl_number: int | None = None,
    ) -> x509.CertificateRevocationList:
        """
        Build and sign a Certificate Revocation List from the provided records.

        The CRL always carries the ``CRLNumber`` (RFC 5280 §5.2.3, mandatory)
        and ``AuthorityKeyIdentifier`` extensions.  Each entry includes the
        ``CRLReason`` entry extension when the stored reason is meaningful
        (``unspecified`` is omitted, as RFC 5280 §5.3.1 recommends).

        Parameters
        ----------
        revoked_certs : Iterable
            Revoked certificate records as returned by
            ``BaseDB.get_revoked_certificates`` — ORM records, SQLAlchemy rows
            or ``(serial, revocation_date[, reason])`` tuples.
        days_valid : int
            Number of days until ``nextUpdate``.  Default: ``1``.
        crl_number : int | None
            Explicit CRL sequence number.  ``None`` derives a monotonically
            increasing number from the current time in microseconds, so no
            external state is required.

        Returns
        -------
        x509.CertificateRevocationList
            The signed CRL object.  The caller is responsible for persisting it.
        """
        now = datetime.datetime.now(datetime.UTC)
        next_update = now + datetime.timedelta(days=days_valid)
        number = crl_number if crl_number is not None else time.time_ns() // 1000
        self._logger.info(
            "Building CRL #%d: valid until %s", number, next_update.isoformat()
        )

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._ca.ca_cert.subject)
            .last_update(now)
            .next_update(next_update)
            .add_extension(x509.CRLNumber(number), critical=False)
            .add_extension(self._authority_key_identifier(), critical=False)
        )
        count = 0
        for record in revoked_certs:
            builder = builder.add_revoked_certificate(self._revoked_entry(record))
            count += 1

        crl: x509.CertificateRevocationList = self._sign(builder)
        self._logger.debug("CRL signed successfully with %d entries", count)
        return crl

    async def abuild_crl(
        self,
        revoked_certs: AsyncIterable[Any],
        days_valid: int = 1,
        crl_number: int | None = None,
    ) -> x509.CertificateRevocationList:
        """
        Async counterpart of :meth:`build_crl` that consumes an async iterable
        (e.g. ``AsyncDBHandler.get_revoked_certificates``).
        """
        records = [record async for record in revoked_certs]
        return self.build_crl(records, days_valid=days_valid, crl_number=crl_number)

    def validate_cert(self, cert: x509.Certificate) -> None:
        """
        Verify that *cert* was issued directly by this CA, is within its
        validity window, and carries a cryptographically correct signature.

        Signature verification uses ``Certificate.verify_directly_issued_by``
        and therefore works for RSA (PKCS#1 v1.5 and PSS), ECDSA and Ed25519.
        For certificates issued by an intermediate CA use
        :meth:`validate_chain`.

        Raises
        ------
        ValidationCertError
            If the issuer, validity window or signature check fails.
        """
        self._logger.debug("Validating certificate serial=%s", cert.serial_number)

        if cert.issuer != self._ca.ca_cert.subject:
            raise ValidationCertError(
                "Certificate issuer does not match the CA subject."
            )
        self._check_ca_validity()
        self._check_validity_window(cert)
        self._check_signature(cert, self._ca.ca_cert)

        self._logger.debug(
            "Certificate serial=%s passed all validation checks", cert.serial_number
        )

    def validate_chain(
        self,
        cert: x509.Certificate,
        intermediates: Sequence[x509.Certificate] = (),
    ) -> list[x509.Certificate]:
        """
        Validate *cert* up to this CA, optionally through intermediate CAs.

        For every link the method checks the validity window, the signature,
        that the issuer is a CA (``BasicConstraints.ca`` and
        ``KeyUsage.key_cert_sign``), that ``path_length`` constraints are
        respected and that every certificate below a CA with
        ``NameConstraints`` uses permitted DNS / IP / e-mail names.  The chain must terminate at this factory's CA certificate
        (the trust anchor).

        Parameters
        ----------
        cert : x509.Certificate
            The certificate to validate (usually a leaf).
        intermediates : Sequence[x509.Certificate]
            Untrusted intermediate CA certificates that may be needed to
            build the path.  Order does not matter.

        Returns
        -------
        list[x509.Certificate]
            The validated path, leaf first and the CA root last.

        Raises
        ------
        ValidationCertError
            If no valid path to the CA exists.
        """
        root = self._ca.ca_cert
        pool = list(intermediates)
        path = [cert]
        current = cert

        for intermediates_below in range(_MAX_CHAIN_DEPTH):
            self._check_validity_window(current)
            if current.issuer == root.subject:
                self._check_ca_validity()
                self._check_signature(current, root)
                self._check_issuer_constraints(root, intermediates_below)
                self._check_path_names(path, root)
                path.append(root)
                return path

            issuer = next((c for c in pool if c.subject == current.issuer), None)
            if issuer is None:
                raise ValidationCertError(
                    f"No issuer found for `{current.issuer.rfc4514_string()}`."
                )
            self._check_signature(current, issuer)
            self._check_issuer_constraints(issuer, intermediates_below)
            self._check_path_names(path, issuer)
            pool.remove(issuer)
            path.append(issuer)
            current = issuer

        raise ValidationCertError("Certificate chain is too long.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @property
    def _signer(self) -> CASigner:
        signer = getattr(self._ca, "ca_signer", None)
        if signer is not None:
            return cast(CASigner, signer)
        return KeySigner(cast(ICALoader, self._ca).ca_key)

    def _sign(self, builder: Any) -> Any:
        """Sign a certificate or CRL builder with the CA (key or external signer)."""
        return sign_builder(builder, self._signer)

    def _fit_ca_lifetime(
        self, not_before: datetime.datetime, not_after: datetime.datetime
    ) -> datetime.datetime:
        """
        Return *not_after* clamped to the CA's own expiry (RFC 5280 path
        validation rejects certificates that outlive their issuer).

        Raises
        ------
        InvalidRangeTimeCertificate
            If the CA has already expired at *not_before*.
        """
        ca_not_after = self._ca.ca_cert.not_valid_after_utc
        if not_before >= ca_not_after:
            raise InvalidRangeTimeCertificate(
                not_before, ca_not_after, datetime.datetime.now(datetime.UTC)
            )
        if not_after > ca_not_after:
            self._logger.warning(
                "Requested not_after=%s exceeds the CA expiry %s; clamped",
                not_after.isoformat(),
                ca_not_after.isoformat(),
            )
            return ca_not_after
        return not_after

    def _check_ca_validity(self) -> None:
        try:
            self._check_validity_window(self._ca.ca_cert)
        except ValidationCertError as exc:
            raise ValidationCertError(f"CA certificate: {exc.message}") from exc

    @staticmethod
    def _ca_key_usage() -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=False,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )

    def _authority_key_identifier(self) -> x509.AuthorityKeyIdentifier:
        """AKI pointing at this CA (from its SKI, or computed from its key)."""
        try:
            ca_ski = self._ca.ca_cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
            return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_ski
            )
        except x509.ExtensionNotFound:
            return x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self._ca.ca_cert.public_key()  # type: ignore[arg-type]
            )

    def _distribution_extensions(self) -> list[tuple[x509.ExtensionType, bool]]:
        """CRLDistributionPoints / AuthorityInformationAccess, when configured."""
        result: list[tuple[x509.ExtensionType, bool]] = []
        if self._crl_urls:
            result.append(
                (
                    x509.CRLDistributionPoints(
                        [
                            x509.DistributionPoint(
                                full_name=[x509.UniformResourceIdentifier(url)],
                                relative_name=None,
                                reasons=None,
                                crl_issuer=None,
                            )
                            for url in self._crl_urls
                        ]
                    ),
                    False,
                )
            )
        access = [
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(url),
            )
            for url in self._ca_issuers_urls
        ] + [
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(url),
            )
            for url in self._ocsp_urls
        ]
        if access:
            result.append((x509.AuthorityInformationAccess(access), False))
        return result

    @staticmethod
    def _build_policies(
        policies: Sequence[str], cps_uri: str | None
    ) -> x509.CertificatePolicies | None:
        if not policies:
            if cps_uri is not None:
                raise ValueError("cps_uri requires at least one certificate policy")
            return None
        qualifiers: list[str | x509.UserNotice] | None = (
            [cps_uri] if cps_uri is not None else None
        )
        return x509.CertificatePolicies(
            [
                x509.PolicyInformation(x509.ObjectIdentifier(oid), qualifiers)
                for oid in policies
            ]
        )

    def _policy_extensions(self) -> list[tuple[x509.ExtensionType, bool]]:
        """CertificatePolicies (non-critical), when configured."""
        return [] if self._policies is None else [(self._policies, False)]

    def _check_own_name_constraints(
        self, subject: x509.Name, san: x509.SubjectAlternativeName | None
    ) -> None:
        """Refuse to sign names this CA's own NameConstraints forbid."""
        constraints = issuer_name_constraints(self._ca.ca_cert)
        if constraints is not None:
            check_name_constraints(
                constraints, subject, san, self._ca.ca_cert.subject.rfc4514_string()
            )

    @staticmethod
    def _check_path_names(
        below: Sequence[x509.Certificate], issuer: x509.Certificate
    ) -> None:
        """Apply *issuer*'s NameConstraints to every certificate below it."""
        for cert in below:
            check_certificate(cert, issuer)

    @staticmethod
    def _revoked_entry(record: Any) -> x509.RevokedCertificate:
        serial = int(_record_field(record, "serial_number", 0))
        revocation_date = _record_field(record, "revocation_date", 1)
        try:
            raw_reason = _record_field(record, "revocation_reason", 2)
        except IndexError:
            raw_reason = None

        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revocation_date)
        )
        reason = _parse_reason(raw_reason)
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        return entry.build()

    @staticmethod
    def _check_validity_window(cert: x509.Certificate) -> None:
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

    @staticmethod
    def _check_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
        try:
            cert.verify_directly_issued_by(issuer)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise ValidationCertError(
                f"Signature verification failed: {exc or type(exc).__name__}"
            ) from exc

    @staticmethod
    def _check_issuer_constraints(
        issuer: x509.Certificate, intermediates_below: int
    ) -> None:
        """Ensure *issuer* may sign certificates at this depth (RFC 5280 §4.2.1.9)."""
        try:
            bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            bc = None
        if bc is None or not bc.ca:
            raise ValidationCertError(
                f"Issuer `{issuer.subject.rfc4514_string()}` is not a CA."
            )
        if bc.path_length is not None and intermediates_below > bc.path_length:
            raise ValidationCertError(
                f"Path length constraint of `{issuer.subject.rfc4514_string()}` "
                f"exceeded ({intermediates_below} > {bc.path_length})."
            )
        try:
            ku = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
            if not ku.key_cert_sign:
                raise ValidationCertError(
                    f"Issuer `{issuer.subject.rfc4514_string()}` lacks keyCertSign."
                )
        except x509.ExtensionNotFound:
            pass

    def _build_subject(self, common_name: str, email: str | None) -> x509.Name:
        """
        Construct the Subject ``x509.Name`` for a new end-entity certificate.

        Attributes (absent CA attributes are skipped):
        1. Country (C) — inherited from the CA's base info.
        2. Organization (O) — inherited from the CA's base info.
        3. Common Name (CN) — always present, taken from *common_name*.
        4. Email Address — only if *email* is not ``None``.
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
            attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, str(email)))

        return x509.Name(attrs)

    @staticmethod
    def _build_csr(
        subject: x509.Name,
        private_key: PrivateKey,
    ) -> x509.CertificateSigningRequest:
        """
        Create a Certificate Signing Request for *subject* signed with *private_key*.

        The CSR proves possession of the private key.  It carries no
        extensions — extensions are added to the final certificate by the CA.
        """
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, signing_hash(private_key))  # type: ignore[arg-type]
        )

    @staticmethod
    def _leaf_key_usage(public_key: object) -> x509.KeyUsage:
        """
        KeyUsage for an end-entity certificate.

        RSA keys may be used for key transport (``keyEncipherment``); ECDSA
        and Ed25519 keys only sign (``digitalSignature``).
        """
        return x509.KeyUsage(
            digital_signature=True,
            key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )

    def _build_extensions(
        self,
        csr: x509.CertificateSigningRequest,
        is_server_cert: bool,
        is_client_cert: bool,
        san_dns: list[str] | None,
        san_ip: list[Any] | None,
    ) -> list[tuple[x509.ExtensionType, bool]]:
        """
        Assemble the list of X.509 v3 extensions for a new end-entity certificate.

        Always-present extensions
        ~~~~~~~~~~~~~~~~~~~~~~~~~
        - ``BasicConstraints(ca=False)`` — critical.
        - ``KeyUsage`` — critical; see :meth:`_leaf_key_usage`.
        - ``SubjectKeyIdentifier`` / ``AuthorityKeyIdentifier``.

        Conditionally-added extensions
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        - ``ExtendedKeyUsage`` — ``ServerAuth`` and/or ``ClientAuth``.
        - ``SubjectAlternativeName`` — non-critical (the Subject is never
          empty, RFC 5280 §4.2.1.6).  For server certificates the CN is
          prepended as a DNS SAN.
        - ``CRLDistributionPoints`` / ``AuthorityInformationAccess`` /
          ``CertificatePolicies`` — when the factory was configured with the
          corresponding URLs / policy OIDs.
        """
        result: list[tuple[x509.ExtensionType, bool]] = [
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (self._leaf_key_usage(csr.public_key()), True),
        ]

        eku: list[x509.ObjectIdentifier] = []
        if is_server_cert:
            eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if is_client_cert:
            eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        if eku:
            result.append((x509.ExtendedKeyUsage(eku), False))

        san: list[x509.GeneralName] = []
        if is_server_cert:
            cn = _first_cn(csr.subject)
            if cn:  # pragma: no branch - _build_subject always sets a CN
                san.append(x509.DNSName(cn))
        for dns in san_dns or []:
            name = x509.DNSName(dns)
            if name not in san:
                san.append(name)
        if san_ip:
            san.extend(x509.IPAddress(ipaddress.ip_address(str(ip))) for ip in san_ip)
        if san:
            result.append((x509.SubjectAlternativeName(san), False))

        result.append(
            (x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), False)
        )
        result.append((self._authority_key_identifier(), False))
        result.extend(self._distribution_extensions())
        result.extend(self._policy_extensions())

        return result

    @staticmethod
    def inspect_certificate(cert: x509.Certificate) -> CertificateDetails:
        """
        Extract and return a structured, human-readable summary of *cert*.

        The method never performs cryptographic verification — use
        :meth:`validate_cert` for that.  It is therefore safe to call on
        certificates from *any* issuer.

        Examples
        --------
        >>> details = CertificateFactory.inspect_certificate(cert)
        >>> details.common_name
        'nginx.internal'
        """

        def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
            attrs = name.get_attributes_for_oid(oid)
            return cast(str, attrs[0].value) if attrs else None

        is_ca = False
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = bc.value.ca
        except x509.ExtensionNotFound:
            pass

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
            key_usage = [bit for bit in _KU_BITS if getattr(ku, bit)]
        except x509.ExtensionNotFound:
            pass

        extended_key_usage: list[str] = []
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            extended_key_usage = [oid.dotted_string for oid in eku]
        except x509.ExtensionNotFound:
            pass

        raw_fp = cert.fingerprint(hashes.SHA256())
        fingerprint_sha256 = ":".join(f"{b:02X}" for b in raw_fp)

        subject_key_identifier: str | None = None
        try:
            ski = cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
            subject_key_identifier = ski.digest.hex()
        except x509.ExtensionNotFound:
            pass

        public_key_algorithm, public_key_size = public_key_info(cert.public_key())

        return CertificateDetails(
            serial_number=cert.serial_number,
            common_name=_attr(cert.subject, NameOID.COMMON_NAME),
            organization=_attr(cert.subject, NameOID.ORGANIZATION_NAME),
            country=_attr(cert.subject, NameOID.COUNTRY_NAME),
            issuer_cn=_attr(cert.issuer, NameOID.COMMON_NAME),
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
            public_key_algorithm=public_key_algorithm,
        )

    def export_pkcs12(
        self,
        cert: x509.Certificate,
        private_key: PrivateKey,
        password: bytes | None = None,
        name: str | None = None,
    ) -> bytes:
        """
        Pack *cert* and *private_key* into a PKCS#12 (PFX) bundle.

        The CA certificate is included as the issuer in the chain.

        Parameters
        ----------
        cert : x509.Certificate
            The leaf certificate to export.
        private_key : PrivateKey
            The private key corresponding to *cert*'s public key.
        password : bytes | None
            Password to encrypt the bundle.  ``None`` produces an unencrypted
            bundle and logs a warning (not recommended for production); an
            empty password raises ``ValueError``.
        name : str | None
            Friendly name (alias).  Defaults to the certificate's Common Name.

        Returns
        -------
        bytes
            Raw DER-encoded PKCS#12 bytes.
        """
        if password is not None and not password:
            raise ValueError(
                "PKCS#12 password must not be empty; pass None to export an "
                "unencrypted bundle explicitly"
            )
        if name is None:
            name = _first_cn(cert.subject) or "certificate"

        encryption_algorithm: serialization.KeySerializationEncryption
        if password is None:
            self._logger.warning(
                "Exporting an unencrypted PKCS#12 bundle (CN=%s): the private "
                "key is stored in plaintext",
                name,
            )
            encryption_algorithm = serialization.NoEncryption()
        else:
            encryption_algorithm = serialization.BestAvailableEncryption(password)

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
        Return the certificate chain from *cert* up to the CA root.

        For a single-level PKI (leaf → root CA) this returns ``[cert, ca_cert]``
        — leaf first, root last (the ``fullchain.pem`` convention).
        """
        self._logger.debug("Building cert chain for serial=%s", cert.serial_number)
        return [cert, self._ca.ca_cert]

    def _resign(
        self,
        cert: x509.Certificate,
        not_before: datetime.datetime,
        not_after: datetime.datetime,
        serial_type: CertType,
        fallback_name: str,
    ) -> x509.Certificate:
        """
        Re-sign *cert*'s Subject, public key and extensions with this CA.

        Issuer-bound extensions (AKI, CRL distribution points, AIA) are
        replaced with ones that point at this CA, as are CertificatePolicies
        when this factory has policies configured.  ``not_after`` is clamped
        to the CA's own expiry, and the names are checked against this CA's
        NameConstraints before anything is signed.
        """
        check_certificate(cert, self._ca.ca_cert)
        not_after = self._fit_ca_lifetime(not_before, not_after)
        cn_raw = _first_cn(cert.subject) or fallback_name
        new_serial = SerialWithEncoding.generate(
            name=cn_raw.lower().replace(os.sep, "_"),
            serial_type=serial_type,
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(cert.subject)
            .issuer_name(self._ca.ca_cert.subject)
            .public_key(cert.public_key())  # type: ignore[arg-type]
            .serial_number(new_serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )
        replaced = set(_ISSUER_BOUND_EXTENSIONS)
        if self._policies is not None:
            replaced.add(ExtensionOID.CERTIFICATE_POLICIES)
        for ext in cert.extensions:
            if ext.oid in replaced:
                continue
            builder = builder.add_extension(ext.value, critical=ext.critical)

        builder = builder.add_extension(
            self._authority_key_identifier(), critical=False
        )
        for ext_value, critical in (
            self._distribution_extensions() + self._policy_extensions()
        ):
            builder = builder.add_extension(ext_value, critical=critical)

        return cast(x509.Certificate, self._sign(builder))

    def renew_certificate(
        self,
        cert: x509.Certificate,
        days_valid: int = 365,
        valid_from: datetime.datetime | None = None,
    ) -> x509.Certificate:
        """
        Issue a renewal of *cert* with a fresh validity window but the same
        Subject, public key, and extensions.

        Renewal re-uses the existing public key — appropriate when the key has
        not been compromised.  The renewal receives a new serial number whose
        type prefix is preserved from the original (e.g. a renewed ``DEVICE``
        certificate stays ``DEVICE``).

        Raises
        ------
        InvalidRangeTimeCertificate
            If the computed expiry is already in the past.
        """
        not_before, not_after = CertLifetime.compute(valid_from, days_valid)
        original_type, _ = SerialWithEncoding.parse(cert.serial_number)

        renewed = self._resign(
            cert,
            not_before,
            not_after,
            serial_type=original_type or CertType.SERVICE,
            fallback_name="renewed",
        )
        self._logger.info(
            "Certificate renewed: CN=%s, old_serial=%s → new_serial=%s, valid_until=%s",
            _first_cn(cert.subject),
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
        key_algorithm: KeyAlgorithm = DEFAULT_KEY_ALGORITHM,
        name_constraints: NameConstraintsConfig | None = None,
    ) -> tuple[x509.Certificate, PrivateKey]:
        """
        Issue a subordinate (intermediate) CA certificate signed by this CA.

        The resulting certificate has ``BasicConstraints(ca=True)`` and
        ``KeyUsage(key_cert_sign=True, crl_sign=True)``.  ``path_length``
        limits how deep the sub-hierarchy can go (``0`` = may only sign
        leaves, ``None`` = unlimited).  When configured, the CRL distribution
        point / AIA of this CA are included so the intermediate itself can be
        checked for revocation, and the configured certificate policies are
        added.

        *name_constraints* adds a critical ``NameConstraints`` extension that
        limits which DNS names, IP addresses and e-mail addresses the
        intermediate (and anything below it) may certify.  It is enforced by
        :meth:`validate_chain` and by a ``CertificateFactory`` running on the
        intermediate when it issues, renews or co-signs.

        Returns
        -------
        tuple[x509.Certificate, PrivateKey]
            ``(intermediate_ca_cert, intermediate_ca_key)``.
        """
        self._logger.info(
            "Issuing intermediate CA: CN=%s, path_length=%s", common_name, path_length
        )
        private_key = generate_private_key(key_algorithm, key_size)
        cert = self._build_intermediate(
            private_key.public_key(),
            common_name,
            days_valid,
            valid_from,
            path_length,
            organization,
            country,
            name_constraints,
        )
        return cert, private_key

    def certify_intermediate_ca(
        self,
        subject_key: x509.CertificateSigningRequest | PublicKey,
        common_name: str,
        days_valid: int = 1825,
        valid_from: datetime.datetime | None = None,
        path_length: int | None = 0,
        organization: str | None = None,
        country: str | None = None,
        name_constraints: NameConstraintsConfig | None = None,
    ) -> x509.Certificate:
        """
        Issue a subordinate CA certificate for an existing key pair.

        Unlike :meth:`issue_intermediate_ca` no key is generated: the key
        stays wherever it lives (typically an HSM of the subordinate CA).
        *subject_key* is either a CSR — its signature is checked as proof of
        possession — or a bare public key.  The Subject is always built from
        *common_name* / *organization* / *country*; a CSR's own Subject and
        extensions are ignored.  Extensions are the same as for
        :meth:`issue_intermediate_ca`.

        Raises
        ------
        ValidationCertError
            If the CSR signature is invalid.
        TypeError
            If the key type is not RSA, EC or Ed25519.
        """
        if isinstance(subject_key, x509.CertificateSigningRequest):
            if not subject_key.is_signature_valid:
                raise ValidationCertError("CSR signature is invalid.")
            public_key = subject_key.public_key()
        else:
            public_key = subject_key
        if not isinstance(public_key, PUBLIC_KEY_TYPES):
            raise TypeError(f"unsupported key type {type(public_key).__name__}")
        self._logger.info(
            "Certifying intermediate CA: CN=%s, path_length=%s",
            common_name,
            path_length,
        )
        return self._build_intermediate(
            cast(PublicKey, public_key),
            common_name,
            days_valid,
            valid_from,
            path_length,
            organization,
            country,
            name_constraints,
        )

    def _build_intermediate(
        self,
        public_key: PublicKey,
        common_name: str,
        days_valid: int,
        valid_from: datetime.datetime | None,
        path_length: int | None,
        organization: str | None,
        country: str | None,
        name_constraints: NameConstraintsConfig | None,
    ) -> x509.Certificate:
        info = self._ca.base_info
        attrs: list[x509.NameAttribute[Any]] = []
        resolved_country = country or info.country
        resolved_org = organization or info.organization
        if resolved_country:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, resolved_country))
        if resolved_org:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, resolved_org))
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        subject = x509.Name(attrs)

        not_before, not_after = CertLifetime.compute(valid_from, days_valid)
        not_after = self._fit_ca_lifetime(not_before, not_after)
        serial_number = SerialWithEncoding.generate(
            name=common_name.lower().replace(os.sep, "_"),
            serial_type=CertType.CA,
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca.ca_cert.subject)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=path_length),
                critical=True,
            )
            .add_extension(self._ca_key_usage(), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(self._authority_key_identifier(), critical=False)
        )
        for ext_value, critical in (
            self._distribution_extensions() + self._policy_extensions()
        ):
            builder = builder.add_extension(ext_value, critical=critical)
        if name_constraints is not None:
            builder = builder.add_extension(
                build_name_constraints(name_constraints), critical=True
            )

        cert: x509.Certificate = self._sign(builder)
        self._logger.info(
            "Intermediate CA issued: CN=%s, serial=%s, valid_until=%s",
            common_name,
            cert.serial_number,
            not_after.isoformat(),
        )
        return cert

    def verify_crl(self, crl: x509.CertificateRevocationList) -> None:
        """
        Verify the issuer, signature and validity window of *crl*.

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

        # NB: ``is_signature_valid`` *returns* False on a bad signature, it
        # does not raise — the result must be checked explicitly.
        try:
            is_valid = crl.is_signature_valid(
                self._ca.ca_cert.public_key()  # type: ignore[arg-type]
            )
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise ValidationCertError(
                f"CRL signature verification failed: {exc}"
            ) from exc
        if not is_valid:
            raise ValidationCertError("CRL signature verification failed.")

        self._logger.debug("CRL verified successfully")

    def cosign_certificate(
        self,
        cert: x509.Certificate,
        days_valid: int | None = None,
        valid_from: datetime.datetime | None = None,
        serial_type: CertType | None = None,
    ) -> x509.Certificate:
        """
        Re-sign an existing certificate with this CA's key and certificate.

        The new certificate preserves the original Subject, public key and
        v3 extensions, but replaces the Issuer, the issuer-bound extensions
        (AKI, CRL distribution points, AIA) and the serial number.  The
        validity window is preserved unless *days_valid* is given.

        .. note::
            This operation does **not** verify that the original certificate
            was valid or trusted before co-signing.

        Parameters
        ----------
        cert : x509.Certificate
            The source certificate.
        days_valid : int | None
            Override the validity duration; ``None`` keeps the original window.
        valid_from : datetime.datetime | None
            Start of the overridden window (ignored when *days_valid* is None).
        serial_type : CertType | None
            Serial prefix for the co-signed certificate.  ``None`` uses
            ``CertType.CA`` for CA certificates and ``CertType.SERVICE``
            otherwise.

        Raises
        ------
        InvalidRangeTimeCertificate
            If *days_valid* is provided and the computed expiry is in the past.
        """
        self._logger.info(
            "Co-signing certificate: CN=%s, original_serial=%s",
            _first_cn(cert.subject) or "<no CN>",
            cert.serial_number,
        )

        if days_valid is not None:
            not_before, not_after = CertLifetime.compute(valid_from, days_valid)
        else:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

        if serial_type is None:
            serial_type = (
                CertType.CA
                if self.inspect_certificate(cert).is_ca
                else CertType.SERVICE
            )

        cosigned = self._resign(
            cert,
            not_before,
            not_after,
            serial_type=serial_type,
            fallback_name="cosigned",
        )
        self._logger.info(
            "Certificate co-signed: new_serial=%s, issuer=%s, valid_until=%s",
            cosigned.serial_number,
            self._ca.ca_cert.subject.rfc4514_string(),
            not_after.isoformat(),
        )
        return cosigned
