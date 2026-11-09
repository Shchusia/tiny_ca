"""Secure defaults and parameter bounds introduced in 1.0.0."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError
import pytest

from tiny_ca import CAConfig, CertificateFactory, ClientConfig, KeyAlgorithm
from tiny_ca.ca_factory.utils.life_time import CertLifetime
from tiny_ca.const import (
    DEFAULT_KEY_ALGORITHM,
    DEFAULT_LEAF_DAYS_VALID,
    DEFAULT_RSA_KEY_SIZE,
    MAX_DAYS_VALID,
    MAX_RSA_KEY_SIZE,
)
from tiny_ca.utils.keys import generate_private_key, signing_hash


def test_default_algorithm_is_p384_with_sha384():
    assert DEFAULT_KEY_ALGORITHM is KeyAlgorithm.EC_P384
    cert, key = CertificateFactory.build_self_signed_ca()
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.curve.name == "secp384r1"
    assert cert.signature_hash_algorithm.name == "sha384"


def test_config_defaults():
    client = ClientConfig(common_name="svc")
    assert client.key_algorithm is KeyAlgorithm.EC_P384
    assert client.key_size == DEFAULT_RSA_KEY_SIZE == 3072
    assert client.days_valid == DEFAULT_LEAF_DAYS_VALID == 365
    assert CAConfig().days_valid == 3650


def test_rsa_default_size_and_hash():
    key = generate_private_key(KeyAlgorithm.RSA)
    assert key.key_size == 3072
    assert signing_hash(key).name == "sha384"


def test_small_rsa_logs_warning(caplog):
    with caplog.at_level("WARNING", logger="TinyCA"):
        generate_private_key(KeyAlgorithm.RSA, 2048)
    assert any("below the recommended" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("size", [1024, MAX_RSA_KEY_SIZE + 8])
def test_rsa_size_bounds(size):
    with pytest.raises(ValueError, match="between"):
        generate_private_key(KeyAlgorithm.RSA, size)
    with pytest.raises(ValidationError):
        ClientConfig(common_name="x", key_size=size)


@pytest.mark.parametrize("days", [0, -5, MAX_DAYS_VALID + 1])
def test_days_valid_bounds(days):
    with pytest.raises(ValueError, match="days_valid"):
        CertLifetime.compute(days_valid=days)
    with pytest.raises(ValidationError):
        ClientConfig(common_name="x", days_valid=days)
    with pytest.raises(ValidationError):
        CAConfig(days_valid=days)
