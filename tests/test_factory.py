"""
Tests for tiny_ca/cert/factory.py  (CertificateFactory)

Coverage target: 100 %

Run with:
    pytest test_factory.py -v --cov=tiny_ca.cert.factory --cov-report=term-missing
"""

from __future__ import annotations

import asyncio
import datetime
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tiny_ca import CertificateFactory, ICALoader
from tiny_ca.const import CertType
from tiny_ca.exc import ValidationCertError
from tiny_ca.models.certtificate import CertificateInfo


# ---------------------------------------------------------------------------
# Fixtures
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
    """Minimal ICALoader-compatible stub."""

    class _Loader:
        @property
        def ca_cert(self) -> x509.Certificate:
            return ca_cert

        @property
        def ca_key(self) -> rsa.RSAPrivateKey:
            return ca_key

        @property
        def base_info(self) -> CertificateInfo:
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
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_revoked_record(serial: int, date: datetime.datetime):
    rec = MagicMock()
    rec.serial_number = serial
    rec.revocation_date = date
    return rec


# ===========================================================================
# __init__
# ===========================================================================


class TestInit:
    def test_valid_loader_accepted(self, ca_loader):
        f = CertificateFactory(ca_loader)
        assert f._ca is ca_loader

    def test_invalid_loader_raises_type_error(self):
        with pytest.raises(TypeError):
            CertificateFactory(object())  # type: ignore

    def test_custom_logger(self, ca_loader):
        import logging

        lg = logging.getLogger("factory_test")
        f = CertificateFactory(ca_loader, logger=lg)
        assert f._logger is lg

    def test_default_logger(self, ca_loader):
        from tiny_ca.settings import DEFAULT_LOGGER

        f = CertificateFactory(ca_loader)
        assert f._logger is DEFAULT_LOGGER


# ===========================================================================
# build_self_signed_ca  (static)
# ===========================================================================


class TestBuildSelfSignedCA:
    def test_returns_cert_and_key(self):
        cert, key = CertificateFactory.build_self_signed_ca()
        assert isinstance(cert, x509.Certificate)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_is_ca_cert(self):
        cert, _ = CertificateFactory.build_self_signed_ca()
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_custom_cn_and_org(self):
        cert, _ = CertificateFactory.build_self_signed_ca(
            common_name="My Root", organization="Acme"
        )
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert cn == "My Root"
        assert org == "Acme"

    def test_custom_key_size(self):
        _, key = CertificateFactory.build_self_signed_ca(key_size=2048)
        assert key.key_size == 2048

    def test_custom_days_valid(self):
        cert, _ = CertificateFactory.build_self_signed_ca(days_valid=90)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert delta.days == 90

    def test_explicit_valid_from(self):
        vf = datetime.datetime.now(datetime.UTC)
        cert, _ = CertificateFactory.build_self_signed_ca(valid_from=vf, days_valid=30)
        assert cert.not_valid_before_utc.date() == vf.date()

    def test_accepts_logger_argument(self):
        import logging

        lg = logging.getLogger("static_test")
        # Should not raise
        CertificateFactory.build_self_signed_ca(logger=lg)

    def test_key_usage_has_cert_sign(self):
        cert, _ = CertificateFactory.build_self_signed_ca()
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_cert_sign is True
        assert ku.crl_sign is True

    def test_subject_key_identifier_present(self):
        cert, _ = CertificateFactory.build_self_signed_ca()
        cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )  # does not raise


# ===========================================================================
# issue_certificate
# ===========================================================================


class TestIssueCertificate:
    def test_returns_cert_key_csr(self, factory):
        cert, key, csr = factory.issue_certificate("test.example.com")
        assert isinstance(cert, x509.Certificate)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert isinstance(csr, x509.CertificateSigningRequest)

    def test_cn_in_subject(self, factory):
        cert, _, _ = factory.issue_certificate("my.service")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "my.service"

    def test_country_inherited_from_ca(self, factory):
        cert, _, _ = factory.issue_certificate("svc")
        country_attrs = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        assert country_attrs[0].value == "UA"

    def test_org_inherited_from_ca(self, factory):
        cert, _, _ = factory.issue_certificate("svc")
        org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert org_attrs[0].value == "Test Corp"

    def test_email_added_to_subject(self, factory):
        cert, _, _ = factory.issue_certificate("svc", email="a@b.com")
        email_attrs = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        assert email_attrs[0].value == "a@b.com"

    def test_is_not_ca_cert(self, factory):
        cert, _, _ = factory.issue_certificate("leaf")
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_server_cert_adds_server_auth_eku(self, factory):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        cert, _, _ = factory.issue_certificate("srv", is_server_cert=True)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    def test_client_cert_adds_client_auth_eku(self, factory):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        cert, _, _ = factory.issue_certificate("cli", is_client_cert=True)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_both_server_and_client_eku(self, factory):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        cert, _, _ = factory.issue_certificate(
            "both", is_server_cert=True, is_client_cert=True
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_no_eku_without_flags(self, factory):
        cert, _, _ = factory.issue_certificate("plain")
        with pytest.raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)

    def test_san_dns_added(self, factory):
        cert, _, _ = factory.issue_certificate(
            "svc", is_server_cert=True, san_dns=["alt.example.com"]
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "alt.example.com" in dns_names

    def test_san_ip_added(self, factory):
        import ipaddress

        cert, _, _ = factory.issue_certificate(
            "svc", is_server_cert=True, san_ip=["192.168.1.1"]
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address("192.168.1.1") in ips

    def test_cert_type_service(self, factory):
        cert, _, _ = factory.issue_certificate("svc", serial_type=CertType.SERVICE)
        assert cert.serial_number > 0

    def test_days_valid_respected(self, factory):
        cert, _, _ = factory.issue_certificate("svc", days_valid=90)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert delta.days == 90

    def test_san_without_server_cert_flag(self, factory):
        """Only san_dns/san_ip, no server flag — SAN added but not critical."""
        cert, _, _ = factory.issue_certificate("svc", san_dns=["extra.com"])
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san is not None

    def test_no_san_when_nothing_specified(self, factory):
        cert, _, _ = factory.issue_certificate("plain_svc")
        with pytest.raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)


# ===========================================================================
# _build_subject  (private, exercised via issue_certificate)
# ===========================================================================


class TestBuildSubject:
    def test_no_country_in_ca_skips_country(self, ca_cert, ca_key):
        class _NoCountryLoader:
            @property
            def ca_cert(self):
                return ca_cert

            @property
            def ca_key(self):
                return ca_key

            @property
            def base_info(self):
                return CertificateInfo(
                    organization="Org",
                    organizational_unit=None,
                    country=None,
                    state=None,
                    locality=None,
                )

        f = CertificateFactory(_NoCountryLoader())
        cert, _, _ = f.issue_certificate("svc")
        assert not cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)

    def test_no_org_in_ca_skips_org(self, ca_cert, ca_key):
        class _NoOrgLoader:
            @property
            def ca_cert(self):
                return ca_cert

            @property
            def ca_key(self):
                return ca_key

            @property
            def base_info(self):
                return CertificateInfo(
                    organization=None,
                    organizational_unit=None,
                    country="UA",
                    state=None,
                    locality=None,
                )

        f = CertificateFactory(_NoOrgLoader())
        cert, _, _ = f.issue_certificate("svc")
        assert not cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)


# ===========================================================================
# build_crl
# ===========================================================================


class TestBuildCRL:
    def test_empty_crl(self, factory):
        def gen() -> Generator:
            return
            yield

        crl = factory.build_crl(gen())
        assert isinstance(crl, x509.CertificateRevocationList)

    def test_crl_with_revoked_entries(self, factory):
        now = datetime.datetime.now(datetime.UTC)

        def gen():
            yield _make_revoked_record(12345, now)
            yield _make_revoked_record(67890, now)

        crl = factory.build_crl(gen())
        assert len(list(crl)) == 2

    def test_crl_signed_by_ca(self, factory, ca_cert):
        def gen():
            return
            yield

        crl = factory.build_crl(gen())
        assert crl.issuer == ca_cert.subject

    def test_crl_days_valid(self, factory):
        def gen():
            return
            yield

        before = datetime.datetime.now(datetime.UTC)
        crl = factory.build_crl(gen(), days_valid=7)
        after = datetime.datetime.now(datetime.UTC)
        expected_next = before + datetime.timedelta(days=7)
        assert crl.next_update_utc >= expected_next - datetime.timedelta(seconds=2)


# ===========================================================================
# abuild_crl (async)
# ===========================================================================


class TestABuildCRL:
    def test_empty_async_crl(self, factory):
        async def gen():
            return
            yield

        crl = run(factory.abuild_crl(gen()))
        assert isinstance(crl, x509.CertificateRevocationList)

    def test_async_crl_with_entries(self, factory):
        now = datetime.datetime.now(datetime.UTC)

        async def gen():
            yield (str(111), now, "reason1")
            yield (str(222), now, "reason2")

        crl = run(factory.abuild_crl(gen()))
        assert len(list(crl)) == 2

    def test_async_crl_issuer_matches_ca(self, factory, ca_cert):
        async def gen():
            return
            yield

        crl = run(factory.abuild_crl(gen()))
        assert crl.issuer == ca_cert.subject


# ===========================================================================
# validate_cert
# ===========================================================================


class TestValidateCert:
    def test_valid_cert_passes(self, factory):
        cert, _, _ = factory.issue_certificate("valid.svc")
        factory.validate_cert(cert)  # must not raise

    def test_wrong_issuer_raises(self, factory):
        # Build a cert signed by a different CA
        other_key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.datetime.now(datetime.UTC)
        other_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(other_subject)
            .issuer_name(other_subject)  # wrong issuer
            .public_key(other_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(other_key, hashes.SHA256(), default_backend())
        )
        with pytest.raises(ValidationCertError, match="issuer"):
            factory.validate_cert(cert)

    def test_expired_cert_raises(self, factory, ca_cert, ca_key):
        now = datetime.datetime.now(datetime.UTC)
        past = now - datetime.timedelta(days=10)
        expired_end = now - datetime.timedelta(days=1)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
                x509.NameAttribute(NameOID.COMMON_NAME, "expired.svc"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(
                rsa.generate_private_key(65537, 2048, default_backend()).public_key()
            )
            .serial_number(x509.random_serial_number())
            .not_valid_before(past)
            .not_valid_after(expired_end)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        with pytest.raises(ValidationCertError):
            factory.validate_cert(cert)

    def test_not_yet_valid_raises(self, factory, ca_cert, ca_key):
        now = datetime.datetime.now(datetime.UTC)
        future_start = now + datetime.timedelta(days=10)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
                x509.NameAttribute(NameOID.COMMON_NAME, "future.svc"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(
                rsa.generate_private_key(65537, 2048, default_backend()).public_key()
            )
            .serial_number(x509.random_serial_number())
            .not_valid_before(future_start)
            .not_valid_after(future_start + datetime.timedelta(days=365))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        with pytest.raises(ValidationCertError):
            factory.validate_cert(cert)

    def test_bad_signature_raises(self, factory, ca_cert):
        """Cert with correct issuer but signed by a different key."""
        other_key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.datetime.now(datetime.UTC)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
                x509.NameAttribute(NameOID.COMMON_NAME, "badsig.svc"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)  # correct issuer
            .public_key(other_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(other_key, hashes.SHA256(), default_backend())  # wrong signing key
        )
        with pytest.raises(ValidationCertError, match="[Ss]ignature"):
            factory.validate_cert(cert)
