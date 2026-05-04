"""
certificate.py

Pydantic data models for certificate configuration and metadata.

These models act as typed, validated data-transfer objects between the
application layer and the cryptographic factory.  They are intentionally
free of any cryptographic logic — validation (field constraints, type
coercion) is Pydantic's responsibility; generation is ``CertificateFactory``'s.

Class hierarchy
---------------
::

    BaseModel
    ├── CommonNameCertificate          — CN field only
    │   └── BaseCertificateDataModel  — CN + organization + country
    ├── BaseCertificateConfig          — key_size, days_valid, valid_from
    │   └── CAConfig                  — full CA bootstrap config (inherits both branches)
    └── ClientConfig                   — end-entity cert config (CN + crypto params + SANs)

    CertificateInfo                    — read-only metadata extracted from an
                                         existing CA certificate's Subject field
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, IPvAnyAddress

from tiny_ca.const import CertType

# ---------------------------------------------------------------------------
# Reusable base fragments
# ---------------------------------------------------------------------------


class CommonNameCertificate(BaseModel):
    """
    Minimal certificate identity fragment carrying only the Common Name.

    Used as a mix-in base so that all certificate configuration models share
    a consistent ``common_name`` field with the same default and description.

    Attributes
    ----------
    common_name : str
        The ``CN`` (Common Name) field of the certificate Subject.
        Default: ``"Internal CA"``.
    """

    common_name: str = Field(
        default="Internal CA",
        description="Common Name (CN) for the certificate Subject.",
    )


class BaseCertificateDataModel(CommonNameCertificate):
    """
    Certificate Subject identity fields shared by all CA configurations.

    Extends ``CommonNameCertificate`` with *organization* and *country* so
    that all issued end-entity certificates can inherit the issuer's
    organisational identity.

    Attributes
    ----------
    common_name : str
        Inherited from ``CommonNameCertificate``.
    organization : str
        Organization (O) field of the certificate Subject.
        Default: ``"My Company"``.
    country : str
        Two-letter ISO 3166-1 alpha-2 country code (C field).
        Default: ``"UA"``.
    """

    organization: str = Field(
        default="My Company",
        description="Organization (O) field of the certificate Subject.",
    )
    country: str = Field(
        default="UA",
        description="Two-letter ISO 3166-1 alpha-2 country code (C field).",
    )


class BaseCertificateConfig(BaseModel):
    """
    Cryptographic validity parameters shared by all certificate types.

    Provides the three fields that control the key strength and the validity
    window of a certificate.  Used as a mix-in base to avoid duplication
    between ``CAConfig`` and ``ClientConfig``.

    Attributes
    ----------
    key_size : int
        RSA key length in bits.  Use ``2048`` for standard security or
        ``4096`` for long-lived CA certificates.  Default: ``2048``.
    days_valid : int
        Number of calendar days the certificate should remain valid.
        Default: ``3650`` (≈10 years; appropriate for a root CA).
    valid_from : datetime.datetime | None
        Explicit start of the validity period as a timezone-aware
        ``datetime``.  When ``None``, the cryptographic layer uses the
        current UTC time at the moment of issuance.  Default: ``None``.

    Notes
    -----
    ``model_config = ConfigDict(arbitrary_types_allowed=True)`` is required
    because ``datetime.datetime`` is not a Pydantic-native field type.
    """

    key_size: int = Field(
        default=2048,
        description="RSA key length in bits (2048 or 4096).",
    )
    days_valid: int = Field(
        default=3650,
        description="Certificate validity period in calendar days.",
    )
    valid_from: datetime | None = Field(
        default=None,
        description=(
            "Explicit validity start as a timezone-aware datetime. "
            "None defaults to the current UTC time at issuance."
        ),
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ---------------------------------------------------------------------------
# Concrete configuration models
# ---------------------------------------------------------------------------


class CAConfig(BaseCertificateConfig, BaseCertificateDataModel):
    """
    Complete configuration for bootstrapping a self-signed root CA certificate.

    Combines all Subject identity fields (``BaseCertificateDataModel``) with
    the cryptographic validity parameters (``BaseCertificateConfig``).
    Passed directly to ``CertificateFactory.build_self_signed_ca`` via
    ``config.model_dump()``.

    Inherited attributes
    --------------------
    common_name : str
        CN for the CA.  Default: ``"Internal CA"``.
    organization : str
        O field.  Default: ``"My Company"``.
    country : str
        C field (ISO 3166-1 alpha-2).  Default: ``"UA"``.
    key_size : int
        RSA key size in bits.  Default: ``2048``.
    days_valid : int
        Validity in days.  Default: ``3650``.
    valid_from : datetime | None
        Explicit validity start; ``None`` uses current UTC.  Default: ``None``.
    """


class ClientConfig(CommonNameCertificate, BaseCertificateConfig):
    """
    Configuration for issuing an end-entity (client or server) certificate.

    Passed to ``CertificateFactory.issue_certificate`` via
    ``config.model_dump(exclude={"name"})``.

    Attributes
    ----------
    common_name : str
        CN for the certificate Subject.  Inherited from
        ``CommonNameCertificate``.  Default: ``"Internal CA"``.
    key_size : int
        RSA key size in bits.  Inherited from ``BaseCertificateConfig``.
        Default: ``2048``.
    days_valid : int
        Validity period in calendar days.  Default: ``3650``.
    valid_from : datetime | None
        Explicit validity start.  Default: ``None``.
    serial_type : CertType
        Certificate category used when encoding the serial number.
        Default: ``CertType.CA``.
    is_client_cert : bool
        When ``True``, ``ClientAuth`` is added to the Extended Key Usage
        extension.  Default: ``False``.
    is_server_cert : bool
        When ``True``, ``ServerAuth`` is added to the Extended Key Usage
        extension and the CN is included as a DNS Subject Alternative Name
        (RFC 2818 compliance).  Default: ``True``.
    san_dns : list[str] | None
        Additional DNS names for the Subject Alternative Name extension.
        Default: ``None``.
    san_ip : list[IPvAnyAddress] | None
        IP addresses for the Subject Alternative Name extension.  Accepts
        both IPv4 and IPv6.  Default: ``None``.
    email : EmailStr | None
        Optional email address added as an ``emailAddress`` Subject attribute.
        Must be a valid RFC 5322 address if provided.  Default: ``None``.
    name : str | None
        Override for the output file basename used by ``BaseStorage``.
        When ``None``, the storage layer derives the name from *common_name*.
        This field is excluded from ``model_dump`` calls to the factory.
        Default: ``None``.
    """

    serial_type: CertType = Field(
        default=CertType.CA,
        description="Certificate category encoded into the serial number.",
    )
    is_client_cert: bool = Field(
        default=False,
        description="Add ClientAuth to Extended Key Usage when True.",
    )
    is_server_cert: bool = Field(
        default=True,
        description=(
            "Add ServerAuth to Extended Key Usage and include CN as a DNS SAN "
            "when True (required for TLS server certificates per RFC 2818)."
        ),
    )
    san_dns: list[str] | None = Field(
        default=None,
        description="Additional DNS names for the Subject Alternative Name extension.",
    )
    san_ip: list[IPvAnyAddress] | None = Field(
        default=None,
        description="IP addresses (IPv4 or IPv6) for the Subject Alternative Name extension.",
    )
    email: EmailStr | None = Field(
        default=None,
        description="Optional email address added as an emailAddress Subject attribute.",
    )
    name: str | None = Field(
        default=None,
        description=(
            "Explicit output file basename for storage artefacts. "
            "Excluded from model_dump calls to the factory. "
            "None causes the storage layer to derive the name from common_name."
        ),
    )


# ---------------------------------------------------------------------------
# Read-only metadata extracted from an existing CA certificate
# ---------------------------------------------------------------------------


class CertificateInfo(BaseModel):
    """
    Structured metadata extracted from the Subject field of a CA certificate.

    Populated by ``CAFileLoader._extract_info`` and made available via the
    ``ICALoader.base_info`` property.  ``CertificateFactory`` uses these
    values to populate the Subject of every end-entity certificate it issues,
    ensuring that all leaf certificates share the same organisational identity
    as the signing CA.

    All fields are optional (``None``) because not every CA certificate
    includes all Subject attributes.

    Attributes
    ----------
    organization : str | None
        Organization (O) field.  Default: ``"My company"``.
    organizational_unit : str | None
        Organizational Unit (OU) field.  Default: ``"server"``.
    country : str | None
        Two-letter ISO 3166-1 alpha-2 country code (C field).
        Default: ``"UA"``.
    state : str | None
        State or Province (ST) field.  Default: ``None``.
    locality : str | None
        Locality or City (L) field.  Default: ``None``.
    """

    organization: str | None = Field(
        default="My company",
        description="Organization (O) extracted from the CA certificate Subject.",
    )
    organizational_unit: str | None = Field(
        default="server",
        description="Organizational Unit (OU) extracted from the CA certificate Subject.",
    )
    country: str | None = Field(
        default="UA",
        description="Country (C) extracted from the CA certificate Subject.",
    )
    state: str | None = Field(
        default=None,
        description="State or Province (ST) extracted from the CA certificate Subject.",
    )
    locality: str | None = Field(
        default=None,
        description="Locality / City (L) extracted from the CA certificate Subject.",
    )


class CertificateDetails(BaseModel):
    """
    Structured read-only snapshot of an ``x509.Certificate``.

    All fields are extracted from the certificate at creation time and stored
    as plain Python values — no ``cryptography`` objects leak out — so the
    model is trivially serialisable (JSON, msgpack, etc.).
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )

    serial_number: int = Field(
        description="Raw integer serial number as stored in the certificate."
    )

    common_name: str | None = Field(
        default=None, description="First commonName (CN) from the Subject."
    )

    organization: str | None = Field(
        default=None, description="First organizationName (O) from the Subject."
    )

    country: str | None = Field(
        default=None, description="First countryName (C) from the Subject."
    )

    issuer_cn: str | None = Field(
        default=None, description="Common Name extracted from the Issuer."
    )

    not_valid_before: datetime = Field(
        description="Start of the validity window (UTC)."
    )

    not_valid_after: datetime = Field(description="End of the validity window (UTC).")

    is_ca: bool = Field(
        description="True if BasicConstraints marks this certificate as CA."
    )

    san_dns: list[str] = Field(
        default_factory=list, description="DNS names from SubjectAlternativeName."
    )

    san_ip: list[str] = Field(
        default_factory=list, description="IP addresses from SubjectAlternativeName."
    )

    key_usage: list[str] = Field(
        default_factory=list, description="Enabled KeyUsage flags."
    )

    extended_key_usage: list[str] = Field(
        default_factory=list, description="OID strings from ExtendedKeyUsage."
    )

    fingerprint_sha256: str = Field(
        description="SHA256 fingerprint of the certificate."
    )

    subject_key_identifier: str | None = Field(
        default=None, description="SubjectKeyIdentifier hex digest."
    )

    public_key_size: int | None = Field(
        default=None, description="RSA key size in bits (None for non-RSA keys)."
    )
