"""
test_factory.py

Tests for tiny_ca/ca_factory/factory.py:
  - CertificateFactory construction   — valid loader, invalid loader
  - build_self_signed_ca             — fields, extensions, key usage
  - issue_certificate                — subject, extensions, server/client flags, SAN
  - build_crl                        — empty and non-empty revocation lists
  - validate_cert                    — pass, wrong issuer, expired, bad signature
  - _build_subject                   — with/without email, missing CA fields
  - _build_extensions                — EKU combinations, SAN combinations
"""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tiny_ca.ca_factory.factory import CertificateFactory
from tiny_ca.const import CertType
from tiny_ca.exc import ValidationCertError
from tiny_ca.models.certtificate import CertificateInfo


# ---------------------------------------------------------------------------
# Helper: build a CertificateRecord-like namedtuple for CRL tests
# ---------------------------------------------------------------------------


class _FakeRevoked:
    def __init__(self, serial: int):
        self.serial_number = str(serial)
        self.revocation_date = datetime.datetime.now(datetime.timezone.utc)
        self.revocation_reason = 0


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestCertificateFactoryConstruction:
    def test_valid_loader_accepted(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        assert factory is not None

    def test_invalid_loader_raises_type_error(self):
        with pytest.raises(TypeError, match="ICALoader"):
            CertificateFactory(ca_loader="not_a_loader")

    def test_none_loader_raises_type_error(self):
        with pytest.raises(TypeError):
            CertificateFactory(ca_loader=None)  # type: ignore[arg-type]

    def test_custom_logger_stored(self, mock_ca_loader):
        import logging

        log = logging.getLogger("test")
        factory = CertificateFactory(ca_loader=mock_ca_loader, logger=log)
        assert factory._logger is log

    def test_default_logger_used_when_none(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader, logger=None)
        assert factory._logger is not None


# ---------------------------------------------------------------------------
# build_self_signed_ca (static method)
# ---------------------------------------------------------------------------


class TestBuildSelfSignedCA:
    def test_returns_tuple(self):
        cert, key = CertificateFactory.build_self_signed_ca()
        assert isinstance(cert, x509.Certificate)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_subject_equals_issuer(self):
        cert, _ = CertificateFactory.build_self_signed_ca(common_name="My CA")
        assert cert.subject == cert.issuer

    def test_common_name_embedded(self):
        cert, _ = CertificateFactory.build_self_signed_ca(common_name="RootCA")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "RootCA"

    def test_organization_embedded(self):
        cert, _ = CertificateFactory.build_self_signed_ca(organization="ACME Corp")
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert org == "ACME Corp"

    def test_country_embedded(self):
        cert, _ = CertificateFactory.build_self_signed_ca(country="DE")
        c = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
        assert c == "DE"

    def test_basic_constraints_ca_true(self):
        cert, _ = CertificateFactory.build_self_signed_ca()
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_key_usage_cert_sign_true(self):
        cert, _ = CertificateFactory.build_self_signed_ca()
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True

    def test_key_usage_crl_sign_true(self):
        cert, _ = CertificateFactory.build_self_signed_ca()
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.crl_sign is True

    def test_key_usage_digital_signature_false(self):
        cert, _ = CertificateFactory.build_self_signed_ca()
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is False

    def test_subject_key_identifier_present(self):
        cert, _ = CertificateFactory.build_self_signed_ca()
        cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )  # no exception

    def test_days_valid_respected(self):
        cert, _ = CertificateFactory.build_self_signed_ca(days_valid=100)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert delta.days == 100

    def test_serial_number_is_positive(self):
        cert, _ = CertificateFactory.build_self_signed_ca()
        assert cert.serial_number > 0

    def test_custom_valid_from(self):
        custom_start = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        cert, _ = CertificateFactory.build_self_signed_ca(
            valid_from=custom_start, days_valid=365
        )
        assert cert.not_valid_before_utc.year == 2030


# ---------------------------------------------------------------------------
# issue_certificate
# ---------------------------------------------------------------------------


class TestIssueCertificate:
    def test_returns_three_tuple(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        result = factory.issue_certificate(common_name="svc.example.com")
        assert len(result) == 3

    def test_certificate_is_x509(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(common_name="test.local")
        assert isinstance(cert, x509.Certificate)

    def test_key_is_rsa_private_key(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        _, key, _ = factory.issue_certificate(common_name="test.local")
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_csr_is_certificate_signing_request(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        _, _, csr = factory.issue_certificate(common_name="test.local")
        assert isinstance(csr, x509.CertificateSigningRequest)

    def test_cn_in_subject(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(common_name="my.service")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "my.service"

    def test_issuer_matches_ca_subject(self, mock_ca_loader, ca_cert):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(common_name="leaf")
        assert cert.issuer == ca_cert.subject

    def test_basic_constraints_ca_false(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(common_name="leaf")
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_server_cert_has_server_auth_eku(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(
            common_name="api.example.com", is_server_cert=True
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    def test_client_cert_has_client_auth_eku(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(
            common_name="client", is_server_cert=False, is_client_cert=True
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_server_cert_cn_in_san(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(
            common_name="svc.local", is_server_cert=True
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "svc.local" in dns_names

    def test_additional_san_dns(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(
            common_name="svc.local",
            is_server_cert=True,
            san_dns=["alias.local", "other.local"],
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "alias.local" in dns_names
        assert "other.local" in dns_names

    def test_san_ip(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(
            common_name="device",
            is_server_cert=False,
            san_ip=["10.0.0.1"],
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        import ipaddress

        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address("10.0.0.1") in ips

    def test_email_in_subject(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(
            common_name="alice", email="alice@example.com"
        )
        emails = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        assert len(emails) > 0
        assert emails[0].value == "alice@example.com"

    def test_days_valid_respected(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(common_name="x", days_valid=180)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert delta.days == 180

    def test_no_eku_when_neither_server_nor_client(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(
            common_name="plain", is_server_cert=False, is_client_cert=False
        )
        with pytest.raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)


# ---------------------------------------------------------------------------
# build_crl
# ---------------------------------------------------------------------------


class TestBuildCRL:
    def test_empty_crl_is_valid_object(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        crl = factory.build_crl(iter([]))
        assert isinstance(crl, x509.CertificateRevocationList)

    def test_crl_issuer_matches_ca(self, mock_ca_loader, ca_cert):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        crl = factory.build_crl(iter([]))
        assert crl.issuer == ca_cert.subject

    def test_crl_contains_revoked_entry(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        record = _FakeRevoked(serial=999)
        crl = factory.build_crl(iter([record]))
        serials = [r.serial_number for r in crl]
        assert 999 in serials

    def test_crl_days_valid_sets_next_update(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        crl = factory.build_crl(iter([]), days_valid=7)
        delta = crl.next_update_utc - crl.last_update_utc
        assert delta.days == 7

    def test_crl_multiple_revoked_entries(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        records = [_FakeRevoked(i) for i in range(1, 6)]
        crl = factory.build_crl(iter(records))
        serials = [r.serial_number for r in crl]
        for i in range(1, 6):
            assert i in serials


# ---------------------------------------------------------------------------
# validate_cert
# ---------------------------------------------------------------------------


class TestValidateCert:
    def test_valid_cert_passes_silently(self, mock_ca_loader, leaf_cert):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        factory.validate_cert(leaf_cert)  # must not raise

    def test_wrong_issuer_raises_validation_error(self, mock_ca_loader):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        # Build a cert signed by a DIFFERENT key/CA
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

        other_key = rsa_mod.generate_private_key(65537, 2048, default_backend())
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")]
        )
        other_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(other_key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(other_key, hashes.SHA256(), default_backend())
        )
        with pytest.raises(ValidationCertError, match="issuer"):
            factory.validate_cert(other_cert)

    def test_expired_cert_raises_validation_error(
        self, mock_ca_loader, ca_private_key, ca_cert
    ):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        # Build a cert with validity in the past
        past = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
        expired_end = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
        leaf_key = rsa.generate_private_key(65537, 2048, default_backend())
        ski = ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired")])
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(9999)
            .not_valid_before(past)
            .not_valid_after(expired_end)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
                critical=False,
            )
            .sign(ca_private_key, hashes.SHA256(), default_backend())
        )
        with pytest.raises(ValidationCertError):
            factory.validate_cert(expired_cert)

    def test_bad_signature_raises_validation_error(self, mock_ca_loader, ca_cert):
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        # Use a cert signed by the CA but tamper by using a fresh self-signed cert
        # whose issuer field matches our CA (but sig is wrong)
        other_key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.datetime.now(datetime.timezone.utc)
        # Craft issuer name to match the CA subject
        tampered = (
            x509.CertificateBuilder()
            .subject_name(ca_cert.subject)
            .issuer_name(ca_cert.subject)  # correct issuer
            .public_key(other_key.public_key())
            .serial_number(12345)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(other_key, hashes.SHA256(), default_backend())  # wrong signing key
        )
        with pytest.raises(ValidationCertError):
            factory.validate_cert(tampered)
