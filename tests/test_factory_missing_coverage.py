"""
Tests for CertificateFactory.inspect_certificate and
CertificateFactory.cosign_certificate

These two methods (factory.py lines 707-805 and 872-947) were previously
untested. Adding them here raises factory.py coverage back to 100 %.

Run with:
    pytest test_factory_missing_coverage.py -v \
        --cov=tiny_ca.ca_factory.factory --cov-report=term-missing
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from tiny_ca import CertificateFactory, ICALoader
from tiny_ca.exc import InvalidRangeTimeCertificate
from tiny_ca.models.certtificate import CertificateInfo


# ---------------------------------------------------------------------------
# Module-scoped CA fixtures (shared across all test classes)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ca_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(65537, 2048, default_backend())


@pytest.fixture(scope="module")
def ca_cert(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    now = datetime.datetime.now(datetime.UTC)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture(scope="module")
def ca_loader(ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey) -> ICALoader:
    class _Loader:
        @property
        def ca_cert(self):
            return ca_cert

        @property
        def ca_key(self):
            return ca_key

        @property
        def base_info(self):
            return CertificateInfo(
                organization="Test Corp",
                organizational_unit=None,
                country="UA",
                state=None,
                locality=None,
            )

    return _Loader()


@pytest.fixture(scope="module")
def factory(ca_loader: ICALoader) -> CertificateFactory:
    return CertificateFactory(ca_loader)


# ---------------------------------------------------------------------------
# Helper: build a leaf cert signed by the test CA with full control over
# which extensions are included.
# ---------------------------------------------------------------------------


def _make_leaf(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    *,
    common_name: str = "leaf.example.com",
    is_server: bool = True,
    is_client: bool = False,
    san_dns: list[str] | None = None,
    san_ip: list[str] | None = None,
    add_bc: bool = True,
    add_ku: bool = True,
    add_ski: bool = True,
    key: rsa.RSAPrivateKey | None = None,
) -> x509.Certificate:
    import ipaddress as _ip

    if key is None:
        key = rsa.generate_private_key(65537, 2048, default_backend())
    now = datetime.datetime.now(datetime.UTC)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if add_bc:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    if add_ku:
        builder = builder.add_extension(
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
            critical=False,
        )

    # EKU
    eku_oids = []
    if is_server:
        from cryptography.x509.oid import ExtendedKeyUsageOID

        eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if is_client:
        from cryptography.x509.oid import ExtendedKeyUsageOID

        eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if eku_oids:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)

    # SAN
    san_names: list[x509.GeneralName] = []
    if is_server:
        san_names.append(x509.DNSName(common_name))
    for d in san_dns or []:
        san_names.append(x509.DNSName(d))
    for ip in san_ip or []:
        san_names.append(x509.IPAddress(_ip.ip_address(ip)))
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names), critical=False
        )

    if add_ski:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )

    return builder.sign(ca_key, hashes.SHA256(), default_backend())


# ===========================================================================
# inspect_certificate  (lines 707–805)
# ===========================================================================


class TestInspectCertificate:
    """Cover every branch inside CertificateFactory.inspect_certificate."""

    # ── basic return type ──────────────────────────────────────────────────

    def test_returns_certificate_details(self, factory, ca_cert, ca_key):
        from tiny_ca.models.certtificate import CertificateDetails

        leaf = _make_leaf(ca_cert, ca_key)
        details = factory.inspect_certificate(leaf)
        assert isinstance(details, CertificateDetails)

    # ── Subject attributes ─────────────────────────────────────────────────

    def test_common_name_extracted(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key, common_name="myservice.internal")
        assert factory.inspect_certificate(leaf).common_name == "myservice.internal"

    def test_missing_subject_attrs_are_none(self, factory, ca_cert, ca_key):
        """Cert with CN-only Subject → organization and country are None."""
        details = factory.inspect_certificate(_make_leaf(ca_cert, ca_key))
        assert details.organization is None
        assert details.country is None

    def test_issuer_cn_extracted(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        assert factory.inspect_certificate(leaf).issuer_cn == "Test CA"

    # ── BasicConstraints ──────────────────────────────────────────────────

    def test_is_ca_false_for_leaf(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        assert factory.inspect_certificate(leaf).is_ca is False

    def test_is_ca_true_for_ca_cert(self, factory, ca_cert):
        """CA cert itself has BasicConstraints(ca=True)."""
        assert factory.inspect_certificate(ca_cert).is_ca is True

    def test_is_ca_false_when_no_basic_constraints(self, factory, ca_cert, ca_key):
        """Cert without BasicConstraints extension → is_ca defaults to False."""
        leaf = _make_leaf(ca_cert, ca_key, add_bc=False)
        assert factory.inspect_certificate(leaf).is_ca is False

    # ── SubjectAlternativeName ─────────────────────────────────────────────

    def test_san_dns_populated(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key, is_server=True, san_dns=["alt1.example.com"])
        details = factory.inspect_certificate(leaf)
        assert "alt1.example.com" in details.san_dns

    def test_san_ip_populated(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key, is_server=False, san_ip=["10.0.0.1"])
        details = factory.inspect_certificate(leaf)
        assert "10.0.0.1" in details.san_ip

    def test_no_san_extension_gives_empty_lists(self, factory, ca_cert, ca_key):
        """Cert without any SAN → both san_dns and san_ip are empty."""
        leaf = _make_leaf(ca_cert, ca_key, is_server=False)
        details = factory.inspect_certificate(leaf)
        assert details.san_dns == []
        assert details.san_ip == []

    # ── KeyUsage ──────────────────────────────────────────────────────────

    def test_key_usage_populated(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key, add_ku=True)
        details = factory.inspect_certificate(leaf)
        assert "digital_signature" in details.key_usage
        assert "key_encipherment" in details.key_usage

    def test_no_key_usage_extension_gives_empty_list(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key, add_ku=False)
        details = factory.inspect_certificate(leaf)
        assert details.key_usage == []

    # ── ExtendedKeyUsage ──────────────────────────────────────────────────

    def test_extended_key_usage_populated(self, factory, ca_cert, ca_key):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        leaf = _make_leaf(ca_cert, ca_key, is_server=True)
        details = factory.inspect_certificate(leaf)
        assert (
            ExtendedKeyUsageOID.SERVER_AUTH.dotted_string in details.extended_key_usage
        )

    def test_no_eku_extension_gives_empty_list(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key, is_server=False, is_client=False)
        details = factory.inspect_certificate(leaf)
        assert details.extended_key_usage == []

    # ── Fingerprint ───────────────────────────────────────────────────────

    def test_fingerprint_is_colon_hex(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        fp = factory.inspect_certificate(leaf).fingerprint_sha256
        # Format: "AB:CD:EF:..."  — 32 bytes × 3 chars per byte - 1 colon
        assert ":" in fp
        assert all(c in "0123456789ABCDEF:" for c in fp)

    # ── SubjectKeyIdentifier ──────────────────────────────────────────────

    def test_ski_extracted_when_present(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key, add_ski=True)
        ski = factory.inspect_certificate(leaf).subject_key_identifier
        assert ski is not None
        assert isinstance(ski, str)

    def test_ski_is_none_when_absent(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key, add_ski=False)
        assert factory.inspect_certificate(leaf).subject_key_identifier is None

    # ── Public key size ───────────────────────────────────────────────────

    def test_rsa_key_size_extracted(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        assert factory.inspect_certificate(leaf).public_key_size == 2048

    def test_non_rsa_key_size_is_none(self, factory, ca_cert, ca_key):
        """EC public key → public_key_size should be None."""
        ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        now = datetime.datetime.now(datetime.UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec.svc")])
        ec_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(ec_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        assert factory.inspect_certificate(ec_cert).public_key_size is None

    # ── serial_number passthrough ─────────────────────────────────────────

    def test_serial_number_matches(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        assert factory.inspect_certificate(leaf).serial_number == leaf.serial_number


# ===========================================================================
# cosign_certificate  (lines 872–947)
# ===========================================================================


class TestCosignCertificate:
    """Cover every branch inside CertificateFactory.cosign_certificate."""

    # ── basic smoke test ───────────────────────────────────────────────────

    def test_returns_certificate(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        cosigned = factory.cosign_certificate(leaf)
        assert isinstance(cosigned, x509.Certificate)

    # ── issuer replacement ────────────────────────────────────────────────

    def test_issuer_is_ca_subject(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        cosigned = factory.cosign_certificate(leaf)
        assert cosigned.issuer == ca_cert.subject

    def test_subject_preserved(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key, common_name="preserved.svc")
        cosigned = factory.cosign_certificate(leaf)
        assert cosigned.subject == leaf.subject

    # ── serial number ─────────────────────────────────────────────────────

    def test_serial_number_is_fresh(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        cosigned = factory.cosign_certificate(leaf)
        assert cosigned.serial_number != leaf.serial_number

    # ── validity window: preserve original when days_valid is None ─────────

    def test_preserves_original_validity_when_no_override(
        self, factory, ca_cert, ca_key
    ):
        leaf = _make_leaf(ca_cert, ca_key)
        cosigned = factory.cosign_certificate(leaf)
        # Timestamps may differ by microseconds due to UTC rounding; compare dates
        assert cosigned.not_valid_before_utc.date() == leaf.not_valid_before_utc.date()
        assert cosigned.not_valid_after_utc.date() == leaf.not_valid_after_utc.date()

    # ── validity window: override with days_valid ─────────────────────────

    def test_days_valid_overrides_expiry(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        cosigned = factory.cosign_certificate(leaf, days_valid=90)
        delta = cosigned.not_valid_after_utc - cosigned.not_valid_before_utc
        assert delta.days == 90

    def test_valid_from_used_when_days_valid_provided(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        vf = datetime.datetime.now(datetime.UTC)
        cosigned = factory.cosign_certificate(leaf, days_valid=30, valid_from=vf)
        assert cosigned.not_valid_before_utc.date() == vf.date()

    def test_past_days_valid_raises(self, factory, ca_cert, ca_key):
        """days_valid that produces an already-expired cert must raise."""
        leaf = _make_leaf(ca_cert, ca_key)
        past_start = datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC)
        with pytest.raises(InvalidRangeTimeCertificate):
            factory.cosign_certificate(leaf, days_valid=1, valid_from=past_start)

    # ── AKI from SKI (happy path — CA has SKI) ────────────────────────────

    def test_aki_updated_to_ca_ski(self, factory, ca_cert, ca_key):
        leaf = _make_leaf(ca_cert, ca_key)
        cosigned = factory.cosign_certificate(leaf)
        aki = cosigned.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
        # The AKI key_identifier must equal the CA's SKI digest
        ca_ski = ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        assert aki.key_identifier == ca_ski.digest

    # ── AKI fallback: CA has no SKI ───────────────────────────────────────

    def test_aki_fallback_when_ca_has_no_ski(self, ca_cert, ca_key):
        """When the CA cert has no SKI extension, cosign falls back to
        issuer-name + serial form for the AKI."""
        now = datetime.datetime.now(datetime.UTC)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "No-SKI CA")]
        )
        # Build a CA cert *without* SubjectKeyIdentifier
        ca_no_ski = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        class _NoSKILoader:
            @property
            def ca_cert(self):
                return ca_no_ski

            @property
            def ca_key(self):
                return ca_key

            @property
            def base_info(self):
                return CertificateInfo(
                    organization=None,
                    organizational_unit=None,
                    country=None,
                    state=None,
                    locality=None,
                )

        no_ski_factory = CertificateFactory(_NoSKILoader())
        leaf = _make_leaf(ca_cert, ca_key, add_ski=False)
        cosigned = no_ski_factory.cosign_certificate(leaf)
        # Should have an AKI extension (fallback form), not raise
        aki = cosigned.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
        assert aki is not None

    # ── cert with no CN (edge case in logging / serial generation) ─────────

    def test_cosign_cert_without_cn(self, factory, ca_cert, ca_key):
        """Cert whose Subject has no CN — falls back to 'cosigned' placeholder."""
        now = datetime.datetime.now(datetime.UTC)
        no_cn_subject = x509.Name(
            [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org Only")]
        )
        no_cn_cert = (
            x509.CertificateBuilder()
            .subject_name(no_cn_subject)
            .issuer_name(ca_cert.subject)
            .public_key(
                rsa.generate_private_key(65537, 2048, default_backend()).public_key()
            )
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        cosigned = factory.cosign_certificate(no_cn_cert)
        assert isinstance(cosigned, x509.Certificate)

    # ── extension copying ─────────────────────────────────────────────────

    def test_extensions_copied_except_aki(self, factory, ca_cert, ca_key):
        """All extensions except AKI should be present in the co-signed cert."""
        leaf = _make_leaf(ca_cert, ca_key, is_server=True, add_ski=True)
        cosigned = factory.cosign_certificate(leaf)
        # BasicConstraints should be copied through
        bc = cosigned.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False
        # SAN should be copied through
        san = cosigned.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san is not None

    def test_aki_skipped_when_source_cert_has_aki(self, factory, ca_cert, ca_key):
        """Source cert that already has an AKI — the continue branch (line 914)
        must fire to skip it and replace it with the CA's own AKI."""
        # Build a leaf that already carries an AKI referencing the CA's SKI.
        ca_ski = ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        leaf_key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.datetime.now(datetime.UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aki.svc")])
        leaf_with_aki = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        cosigned = factory.cosign_certificate(leaf_with_aki)
        # The AKI in the output must still point at the factory's CA (not be absent)
        aki = cosigned.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
        assert aki.key_identifier == ca_ski.digest
