"""External CA signers: DER re-signing, SignerCALoader and the PKCS#11 signer."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import pytest

from tiny_ca import (
    CertificateFactory,
    KeyAlgorithm,
    KeySigner,
    Pkcs11Signer,
    SignerCALoader,
)
from tiny_ca.exc import ErrorLoadCert, SignerError
from tiny_ca.signing import _key_kind, _split_signed, sign_bytes, verify_signature
from tiny_ca.utils.keys import generate_private_key

ALGORITHMS = [
    (KeyAlgorithm.RSA, 3072),
    (KeyAlgorithm.EC_P256, 0),
    (KeyAlgorithm.EC_P384, 0),
    (KeyAlgorithm.ED25519, 0),
]


class ExternalSigner:
    """Behaves like an HSM: only exposes public_key() and sign()."""

    def __init__(self, key, sign_with=None, fail=False):
        self._key = key
        self._sign_with = sign_with or key
        self._fail = fail
        self.calls = 0

    def public_key(self):
        return self._key.public_key()

    def sign(self, data, algorithm):
        self.calls += 1
        if self._fail:
            raise RuntimeError("token removed")
        return sign_bytes(self._sign_with, data, algorithm)


def _ca(algorithm=KeyAlgorithm.EC_P384, key_size=3072):
    return CertificateFactory.build_self_signed_ca(
        common_name="HSM Root", key_algorithm=algorithm, key_size=key_size
    )


@pytest.mark.parametrize(("algorithm", "key_size"), ALGORITHMS)
def test_external_signer_issues_valid_certificates_and_crl(algorithm, key_size):
    ca_cert, ca_key = _ca(algorithm, key_size or 3072)
    signer = ExternalSigner(ca_key)
    factory = CertificateFactory(SignerCALoader(ca_cert, signer))

    leaf, _, _ = factory.issue_certificate("svc.example", is_server_cert=True)
    leaf.verify_directly_issued_by(ca_cert)
    factory.validate_cert(leaf)

    inter, inter_key = factory.issue_intermediate_ca("Inter")
    inter.verify_directly_issued_by(ca_cert)

    renewed = factory.renew_certificate(leaf, days_valid=30)
    renewed.verify_directly_issued_by(ca_cert)

    crl = factory.build_crl([(leaf.serial_number, leaf.not_valid_before_utc)])
    assert crl.is_signature_valid(ca_cert.public_key())
    assert crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    factory.verify_crl(crl)
    assert signer.calls >= 5


def test_external_and_key_signer_produce_equivalent_certificates():
    ca_cert, ca_key = _ca()
    external = CertificateFactory(SignerCALoader(ca_cert, ExternalSigner(ca_key)))
    leaf, _, _ = external.issue_certificate("svc")
    assert leaf.signature_algorithm_oid == ca_cert.signature_algorithm_oid
    assert leaf.signature_hash_algorithm.name == "sha384"
    # DER round-trip is stable (the spliced encoding is canonical).
    der = leaf.public_bytes(serialization.Encoding.DER)
    assert (
        x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.DER)
        == der
    )


def test_key_signer_takes_fast_path():
    _, key = _ca()
    signer = KeySigner(key)
    assert signer.public_key().public_numbers() == key.public_key().public_numbers()
    signature = signer.sign(b"data", hashes.SHA384())
    assert verify_signature(key.public_key(), signature, b"data", hashes.SHA384())
    assert not verify_signature(key.public_key(), signature, b"other", hashes.SHA384())


def test_signer_error_from_signer_propagates_unchanged():
    ca_cert, ca_key = _ca()
    loader = SignerCALoader(ca_cert, ExternalSigner(ca_key))

    class Refusing(ExternalSigner):
        def sign(self, data, algorithm):
            raise SignerError("token locked")

    loader._signer = Refusing(ca_key)
    with pytest.raises(SignerError, match="^Error `token locked`|token locked") as info:
        CertificateFactory(loader).issue_certificate("svc")
    assert "external signer failed" not in str(info.value)


def test_signer_returning_wrong_signature_is_rejected():
    ca_cert, ca_key = _ca()
    loader = SignerCALoader(ca_cert, ExternalSigner(ca_key))
    factory = CertificateFactory(loader)
    loader._signer = ExternalSigner(ca_key, sign_with=generate_private_key())
    with pytest.raises(SignerError, match="does not match"):
        factory.issue_certificate("svc")


def test_failing_signer_is_wrapped():
    ca_cert, ca_key = _ca()
    loader = SignerCALoader(ca_cert, ExternalSigner(ca_key))
    loader._signer = ExternalSigner(ca_key, fail=True)
    with pytest.raises(SignerError, match="token removed"):
        CertificateFactory(loader).issue_certificate("svc")


class TestSignerCALoader:
    def test_from_pem_path(self, tmp_path):
        ca_cert, ca_key = _ca()
        path = tmp_path / "ca.pem"
        path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        loader = SignerCALoader(path, ExternalSigner(ca_key))
        assert loader.ca_cert == ca_cert
        assert loader.base_info.organization == "My Company"
        assert isinstance(loader.ca_signer, ExternalSigner)

    def test_unreadable_certificate(self, tmp_path):
        with pytest.raises(ErrorLoadCert):
            SignerCALoader(tmp_path / "missing.pem", ExternalSigner(_ca()[1]))

    def test_public_key_mismatch(self):
        ca_cert, _ = _ca()
        with pytest.raises(ErrorLoadCert, match="does not match"):
            SignerCALoader(ca_cert, ExternalSigner(generate_private_key()))

    def test_self_test_detects_wrong_private_key(self):
        ca_cert, ca_key = _ca()
        impostor = ExternalSigner(ca_key, sign_with=generate_private_key())
        with pytest.raises(SignerError, match="self-test"):
            SignerCALoader(ca_cert, impostor)

    def test_self_test_detects_failing_signer(self):
        ca_cert, ca_key = _ca()
        with pytest.raises(SignerError, match="self-test failed: token removed"):
            SignerCALoader(ca_cert, ExternalSigner(ca_key, fail=True))

    def test_factory_rejects_unknown_loader(self):
        with pytest.raises(TypeError, match="ISignerCALoader"):
            CertificateFactory(object())


def test_der_helpers_reject_garbage():
    with pytest.raises(SignerError, match="DER"):
        _split_signed(b"\x02\x01\x00")
    with pytest.raises(SignerError, match="unsupported"):
        _key_kind(object())


# ---------------------------------------------------------------------------
# PKCS#11 — exercised against an in-memory fake of python-pkcs11
# ---------------------------------------------------------------------------


_MECHANISM_HASH = {
    "SHA256_RSA_PKCS": hashes.SHA256,
    "SHA384_RSA_PKCS": hashes.SHA384,
    "SHA512_RSA_PKCS": hashes.SHA512,
    "ECDSA_SHA256": hashes.SHA256,
    "ECDSA_SHA384": hashes.SHA384,
    "ECDSA_SHA512": hashes.SHA512,
}


class FakeToken:
    """Software key that answers like a PKCS#11 private key object."""

    def __init__(self, key):
        self._key = key
        self.mechanisms = []

    def sign(self, data, mechanism):
        self.mechanisms.append(mechanism)
        if mechanism == "EDDSA":
            return self._key.sign(data)
        digest = _MECHANISM_HASH[mechanism]()
        signature = sign_bytes(self._key, data, digest)
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            r, s = decode_dss_signature(signature)
            size = (self._key.curve.key_size + 7) // 8
            return r.to_bytes(size, "big") + s.to_bytes(size, "big")
        return signature


MECHANISMS = SimpleNamespace(
    **{
        n: n
        for n in (
            "SHA256_RSA_PKCS",
            "SHA384_RSA_PKCS",
            "SHA512_RSA_PKCS",
            "ECDSA_SHA256",
            "ECDSA_SHA384",
            "ECDSA_SHA512",
            "EDDSA",
        )
    }
)


@pytest.fixture
def fake_pkcs11(monkeypatch):
    state = SimpleNamespace(key=None, opened=[], closed=0, fail_get_key=False)

    class Session:
        def get_key(self, object_class, label, id):
            assert object_class == "PRIVATE_KEY"
            if state.fail_get_key:
                raise LookupError("no such key")
            state.lookup = (label, id)
            return FakeToken(state.key)

        def close(self):
            state.closed += 1

    class Token:
        def open(self, user_pin):
            state.opened.append(user_pin)
            return Session()

    class Lib:
        def __init__(self, path):
            state.module = path

        def get_token(self, token_label):
            state.token_label = token_label
            return Token()

    module = SimpleNamespace(
        lib=Lib,
        Mechanism=MECHANISMS,
        ObjectClass=SimpleNamespace(PRIVATE_KEY="PRIVATE_KEY"),
    )
    monkeypatch.setitem(sys.modules, "pkcs11", module)
    return state


@pytest.mark.parametrize(("algorithm", "key_size"), ALGORITHMS)
def test_pkcs11_signer_end_to_end(fake_pkcs11, tmp_path, algorithm, key_size):
    ca_cert, ca_key = _ca(algorithm, key_size or 3072)
    fake_pkcs11.key = ca_key
    path = tmp_path / "ca.pem"
    path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    loader = SignerCALoader.from_pkcs11(
        path, "/usr/lib/softhsm/libsofthsm2.so", "ca-token", "1234", key_label="ca"
    )
    assert fake_pkcs11.module == "/usr/lib/softhsm/libsofthsm2.so"
    assert fake_pkcs11.token_label == "ca-token"
    assert fake_pkcs11.opened == ["1234"]
    assert fake_pkcs11.lookup == ("ca", None)

    leaf, _, _ = CertificateFactory(loader).issue_certificate("svc")
    leaf.verify_directly_issued_by(ca_cert)

    with loader.ca_signer:
        pass
    assert fake_pkcs11.closed == 1
    loader.ca_signer.close()
    assert fake_pkcs11.closed == 1


def test_pkcs11_mechanism_selection(fake_pkcs11):
    rsa_key = generate_private_key(KeyAlgorithm.RSA, 3072)
    token = FakeToken(rsa_key)
    signer = Pkcs11Signer(token, rsa_key.public_key())
    for digest in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512()):
        signer.sign(b"x", digest)
    assert token.mechanisms == ["SHA256_RSA_PKCS", "SHA384_RSA_PKCS", "SHA512_RSA_PKCS"]
    with pytest.raises(SignerError, match="no PKCS#11 mechanism"):
        signer.sign(b"x", hashes.SHA1())
    with pytest.raises(SignerError, match="no PKCS#11 mechanism"):
        signer.sign(b"x", None)


def test_pkcs11_open_requires_key_selector(fake_pkcs11):
    with pytest.raises(ValueError, match="key_label or key_id"):
        Pkcs11Signer.open("lib.so", "t", "pin", generate_private_key().public_key())


def test_pkcs11_open_closes_session_when_key_missing(fake_pkcs11):
    fake_pkcs11.fail_get_key = True
    with pytest.raises(LookupError):
        Pkcs11Signer.open(
            "lib.so", "t", "pin", generate_private_key().public_key(), key_id=b"\x01"
        )
    assert fake_pkcs11.closed == 1


def test_from_pkcs11_closes_session_on_mismatch(fake_pkcs11):
    ca_cert, _ = _ca()
    fake_pkcs11.key = generate_private_key()  # not the CA key
    with pytest.raises(SignerError):
        SignerCALoader.from_pkcs11(ca_cert, "lib.so", "t", "pin", key_label="ca")
    assert fake_pkcs11.closed == 1


def test_from_pkcs11_unreadable_certificate(fake_pkcs11, tmp_path):
    with pytest.raises(ErrorLoadCert):
        SignerCALoader.from_pkcs11(
            tmp_path / "nope.pem", "lib.so", "t", "pin", key_label="ca"
        )
