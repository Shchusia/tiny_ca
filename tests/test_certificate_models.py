"""
test_certificate_models.py

Tests for tiny_ca/models/certtificate.py:
  - CommonNameCertificate
  - BaseCertificateDataModel
  - BaseCertificateConfig
  - CAConfig
  - ClientConfig
  - CertificateInfo
"""

from __future__ import annotations

import datetime

import pytest

from tiny_ca.models.certtificate import (
    BaseCertificateConfig,
    BaseCertificateDataModel,
    CAConfig,
    CertificateInfo,
    ClientConfig,
    CommonNameCertificate,
)
from tiny_ca.const import CertType


# ---------------------------------------------------------------------------
# CommonNameCertificate
# ---------------------------------------------------------------------------


class TestCommonNameCertificate:
    def test_default_cn(self):
        m = CommonNameCertificate()
        assert m.common_name == "Internal CA"

    def test_custom_cn(self):
        m = CommonNameCertificate(common_name="My Service")
        assert m.common_name == "My Service"

    def test_empty_string_cn(self):
        m = CommonNameCertificate(common_name="")
        assert m.common_name == ""


# ---------------------------------------------------------------------------
# BaseCertificateDataModel
# ---------------------------------------------------------------------------


class TestBaseCertificateDataModel:
    def test_defaults(self):
        m = BaseCertificateDataModel()
        assert m.common_name == "Internal CA"
        assert m.organization == "My Company"
        assert m.country == "UA"

    def test_custom_values(self):
        m = BaseCertificateDataModel(
            common_name="Root CA",
            organization="ACME",
            country="DE",
        )
        assert m.common_name == "Root CA"
        assert m.organization == "ACME"
        assert m.country == "DE"


# ---------------------------------------------------------------------------
# BaseCertificateConfig
# ---------------------------------------------------------------------------


class TestBaseCertificateConfig:
    def test_defaults(self):
        m = BaseCertificateConfig()
        assert m.key_size == 2048
        assert m.days_valid == 3650
        assert m.valid_from is None

    def test_custom_key_size(self):
        m = BaseCertificateConfig(key_size=4096)
        assert m.key_size == 4096

    def test_custom_days_valid(self):
        m = BaseCertificateConfig(days_valid=90)
        assert m.days_valid == 90

    def test_explicit_valid_from(self):
        dt = datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc)
        m = BaseCertificateConfig(valid_from=dt)
        assert m.valid_from == dt


# ---------------------------------------------------------------------------
# CAConfig
# ---------------------------------------------------------------------------


class TestCAConfig:
    def test_inherits_all_defaults(self):
        m = CAConfig()
        assert m.common_name == "Internal CA"
        assert m.organization == "My Company"
        assert m.country == "UA"
        assert m.key_size == 2048
        assert m.days_valid == 3650
        assert m.valid_from is None

    def test_model_dump_contains_all_fields(self):
        m = CAConfig()
        d = m.model_dump()
        assert "common_name" in d
        assert "organization" in d
        assert "country" in d
        assert "key_size" in d
        assert "days_valid" in d
        assert "valid_from" in d

    def test_override_all_fields(self):
        dt = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        m = CAConfig(
            common_name="RootCA",
            organization="Corp",
            country="GB",
            key_size=4096,
            days_valid=7300,
            valid_from=dt,
        )
        assert m.common_name == "RootCA"
        assert m.key_size == 4096
        assert m.valid_from == dt


# ---------------------------------------------------------------------------
# ClientConfig
# ---------------------------------------------------------------------------


class TestClientConfig:
    def test_defaults(self):
        m = ClientConfig()
        assert m.serial_type == CertType.CA
        assert m.is_client_cert is False
        assert m.is_server_cert is True
        assert m.san_dns is None
        assert m.san_ip is None
        assert m.email is None
        assert m.name is None

    def test_name_excluded_from_model_dump(self):
        m = ClientConfig(name="my-cert")
        d = m.model_dump(exclude={"name"})
        assert "name" not in d

    def test_san_dns_list(self):
        m = ClientConfig(san_dns=["api.local", "svc.local"])
        assert "api.local" in m.san_dns
        assert "svc.local" in m.san_dns

    def test_san_ip_list(self):
        m = ClientConfig(san_ip=["10.0.0.1", "192.168.1.1"])
        assert len(m.san_ip) == 2

    def test_valid_email(self):
        m = ClientConfig(email="user@example.com")
        assert m.email == "user@example.com"

    def test_invalid_email_raises_validation_error(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ClientConfig(email="not_an_email")

    def test_serial_type_device(self):
        m = ClientConfig(serial_type=CertType.DEVICE)
        assert m.serial_type is CertType.DEVICE

    def test_client_and_server_both_true(self):
        m = ClientConfig(is_client_cert=True, is_server_cert=True)
        assert m.is_client_cert is True
        assert m.is_server_cert is True

    def test_model_dump_contains_crypto_fields(self):
        m = ClientConfig()
        d = m.model_dump()
        assert "key_size" in d
        assert "days_valid" in d
        assert "common_name" in d


# ---------------------------------------------------------------------------
# CertificateInfo
# ---------------------------------------------------------------------------


class TestCertificateInfo:
    def test_defaults(self):
        m = CertificateInfo()
        assert m.organization == "My company"
        assert m.organizational_unit == "server"
        assert m.country == "UA"
        assert m.state is None
        assert m.locality is None

    def test_all_none_allowed(self):
        m = CertificateInfo(
            organization=None,
            organizational_unit=None,
            country=None,
            state=None,
            locality=None,
        )
        assert m.organization is None
        assert m.country is None

    def test_custom_state_and_locality(self):
        m = CertificateInfo(state="Kyiv Oblast", locality="Kyiv")
        assert m.state == "Kyiv Oblast"
        assert m.locality == "Kyiv"

    def test_model_dump(self):
        m = CertificateInfo()
        d = m.model_dump()
        assert set(d.keys()) == {
            "organization",
            "organizational_unit",
            "country",
            "state",
            "locality",
        }
