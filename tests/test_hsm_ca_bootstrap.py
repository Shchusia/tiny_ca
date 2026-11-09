"""CA certificates for keys that never leave an HSM (1.0.0)."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import pytest
import pytest_asyncio

from tiny_ca import (
    AuditLog,
    CertificateFactory,
    CertLifecycleManager,
    KeyAlgorithm,
    NameConstraintsConfig,
    SignerCALoader,
    SyncDBHandler,
)
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.exc import ValidationCertError
from tiny_ca.managers.async_lifecycle_manager import AsyncCertLifecycleManager
from tiny_ca.signing import sign_bytes
from tiny_ca.storage import LocalStorage
from tiny_ca.storage.async_local_storage import AsyncLocalStorage
from tiny_ca.utils.keys import generate_private_key, signing_hash


class TokenSigner:
    """Stands in for an HSM key: exposes only public_key() and sign()."""

    def __init__(self, algorithm=KeyAlgorithm.EC_P384):
        self._key = generate_private_key(algorithm)
        self.calls = 0

    def public_key(self):
        return self._key.public_key()

    def sign(self, data, algorithm):
        self.calls += 1
        return sign_bytes(self._key, data, algorithm)

    def csr(self, common_name="ignored"):
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
            )
            .sign(self._key, signing_hash(self._key))
        )


@pytest.fixture(scope="module")
def hsm_root():
    token = TokenSigner()
    cert = CertificateFactory.build_self_signed_ca_with_signer(
        token, common_name="HSM Root", organization="ACME", country="UA"
    )
    return cert, token


@pytest.mark.parametrize(
    "algorithm", [KeyAlgorithm.EC_P384, KeyAlgorithm.RSA, KeyAlgorithm.ED25519]
)
def test_self_signed_root_from_signer(algorithm):
    token = TokenSigner(algorithm)
    cert = CertificateFactory.build_self_signed_ca_with_signer(token)
    assert token.calls == 1
    cert.verify_directly_issued_by(cert)
    assert cert.public_key() == token.public_key()
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca


def test_hsm_root_operates_through_signer_loader(hsm_root):
    cert, token = hsm_root
    factory = CertificateFactory(SignerCALoader(cert, token))
    leaf, _, _ = factory.issue_certificate("svc.example.com", is_server_cert=True)
    factory.validate_cert(leaf)


def test_certify_intermediate_from_csr(hsm_root):
    cert, token = hsm_root
    root = CertificateFactory(SignerCALoader(cert, token))
    sub_token = TokenSigner()
    sub = root.certify_intermediate_ca(
        sub_token.csr(),
        "Issuing CA",
        name_constraints=NameConstraintsConfig(permitted_dns=["example.com"]),
    )
    assert sub.public_key() == sub_token.public_key()
    assert sub.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == (
        "Issuing CA"
    )
    assert (
        sub.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        == "ACME"
    )
    sub.extensions.get_extension_for_class(x509.NameConstraints)

    # The subordinate CA runs from its own token and chains to the root.
    sub_factory = CertificateFactory(SignerCALoader(sub, sub_token))
    leaf, _, _ = sub_factory.issue_certificate("api.example.com", is_server_cert=True)
    assert root.validate_chain(leaf, [sub])[-1] == cert


def test_certify_intermediate_from_public_key(hsm_root):
    cert, token = hsm_root
    key = generate_private_key(KeyAlgorithm.RSA)
    sub = CertificateFactory(SignerCALoader(cert, token)).certify_intermediate_ca(
        key.public_key(), "RSA Sub", path_length=None
    )
    assert sub.public_key() == key.public_key()


def test_certify_rejects_forged_csr(hsm_root):
    cert, token = hsm_root
    der = bytearray(TokenSigner().csr().public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01
    forged = x509.load_der_x509_csr(bytes(der))
    with pytest.raises(ValidationCertError, match="CSR"):
        CertificateFactory(SignerCALoader(cert, token)).certify_intermediate_ca(
            forged, "Bad"
        )


def test_certify_rejects_unsupported_key(hsm_root):
    cert, token = hsm_root
    with pytest.raises(TypeError, match="unsupported key type"):
        CertificateFactory(SignerCALoader(cert, token)).certify_intermediate_ca(
            x25519.X25519PrivateKey.generate().public_key(), "X"
        )


def test_sync_manager_certify(tmp_path, hsm_root):
    cert, token = hsm_root
    db = SyncDBHandler(db_url=f"sqlite:///{tmp_path}/ca.db")
    audit = AuditLog(tmp_path / "audit.jsonl")
    mgr = CertLifecycleManager(
        storage=LocalStorage(tmp_path / "certs"),
        db_handler=db,
        factory=CertificateFactory(SignerCALoader(cert, token)),
        audit_log=audit,
    )
    sub = mgr.certify_intermediate_ca(TokenSigner().csr(), "Issuing CA")
    assert db.get_by_serial(sub.serial_number) is not None
    files = sorted(p.name for p in (tmp_path / "certs").rglob("*") if p.is_file())
    assert files == ["intermediate_ca.pem"]
    assert [e["event"] for e in AuditLog.entries(audit.path)] == [
        "intermediate_ca.certified"
    ]


@pytest_asyncio.fixture
async def adb(tmp_path):
    db = AsyncDBHandler(db_url=f"sqlite+aiosqlite:///{tmp_path}/ca.db")
    await db._db.init_db()
    yield db
    await db._db.engine.dispose()


async def test_async_manager_certify(tmp_path, hsm_root, adb):
    cert, token = hsm_root
    mgr = AsyncCertLifecycleManager(
        storage=AsyncLocalStorage(tmp_path / "certs"),
        db_handler=adb,
        factory=CertificateFactory(SignerCALoader(cert, token)),
    )
    sub = await mgr.certify_intermediate_ca(TokenSigner().public_key(), "Sub")
    assert await adb.get_by_serial(sub.serial_number) is not None
