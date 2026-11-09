"""
Regression tests for the 0.3.x security review: renewal of revoked
certificates, CRL-preserving deletion, CA lifetime enforcement, CA loader
checks, key encryption at rest, atomic key writes and PKCS#12 passwords.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import pytest
import pytest_asyncio

from tiny_ca import (
    CAFileLoader,
    CertificateFactory,
    CertLifecycleManager,
    ClientConfig,
    KeyAlgorithm,
    SyncDBHandler,
)
from tiny_ca.ca_factory.utils.afile_loader import AsyncCAFileLoader
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.exc import (
    CertificateRevokedError,
    ErrorLoadCert,
    InvalidRangeTimeCertificate,
    ValidationCertError,
)
from tiny_ca.managers.async_lifecycle_manager import AsyncCertLifecycleManager
from tiny_ca.storage import LocalStorage
from tiny_ca.storage.async_local_storage import AsyncLocalStorage
from tiny_ca.storage.local_storage import _write_bytes
from tiny_ca.utils.keys import generate_private_key


def _save_ca(tmp: Path, cert, key) -> tuple[Path, Path]:
    store = LocalStorage(tmp / "ca")
    cert_path, _ = store.save_certificate(cert, "ca", is_add_uuid=False)
    key_path, _ = store.save_certificate(key, "ca", is_add_uuid=False)
    return cert_path, key_path


def _factory(tmp: Path, **ca_kw) -> CertificateFactory:
    cert, key = CertificateFactory.build_self_signed_ca(common_name="Root", **ca_kw)
    return CertificateFactory(CAFileLoader(*_save_ca(tmp, cert, key)))


def _expired_ca():
    """A self-signed CA whose validity ended yesterday."""
    cert, key = CertificateFactory.build_self_signed_ca(common_name="Old")
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now - datetime.timedelta(days=1))
    )
    for ext in cert.extensions:
        builder = builder.add_extension(ext.value, critical=ext.critical)
    return builder.sign(key, hashes.SHA256()), key


@pytest.fixture
def env(tmp_path):
    db = SyncDBHandler(db_url=f"sqlite:///{tmp_path}/ca.db")
    mgr = CertLifecycleManager(
        storage=LocalStorage(tmp_path / "certs"),
        db_handler=db,
        factory=_factory(tmp_path),
    )
    return mgr, db


@pytest_asyncio.fixture
async def aenv(tmp_path):
    db = AsyncDBHandler(db_url=f"sqlite+aiosqlite:///{tmp_path}/ca.db")
    await db._db.init_db()
    mgr = AsyncCertLifecycleManager(
        storage=AsyncLocalStorage(tmp_path / "certs"),
        db_handler=db,
        factory=_factory(tmp_path),
    )
    yield mgr, db
    await db._db.engine.dispose()


def _crl_serials(mgr) -> set[int]:
    return {entry.serial_number for entry in mgr.generate_crl()}


# ---------------------------------------------------------------------------
# A revoked certificate must not be resurrected by renewal
# ---------------------------------------------------------------------------


class TestRenewRevoked:
    def test_sync_renew_of_revoked_is_refused(self, env):
        mgr, db = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        with pytest.raises(CertificateRevokedError):
            mgr.renew_certificate(cert.serial_number)
        assert db.get_by_name("svc") is None

    async def test_async_renew_of_revoked_is_refused(self, aenv):
        mgr, db = aenv
        cert, _, _ = await mgr.issue_certificate(ClientConfig(common_name="svc"))
        await mgr.revoke_certificate(
            cert.serial_number, x509.ReasonFlags.key_compromise
        )
        with pytest.raises(CertificateRevokedError):
            await mgr.renew_certificate(cert.serial_number)
        assert await db.get_by_name("svc") is None

    def test_sync_cosign_of_revoked_is_refused(self, env):
        mgr, _ = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        with pytest.raises(CertificateRevokedError):
            mgr.cosign_certificate(cert, is_overwrite=True)

    async def test_async_cosign_of_revoked_is_refused(self, aenv):
        mgr, _ = aenv
        cert, _, _ = await mgr.issue_certificate(ClientConfig(common_name="svc"))
        await mgr.revoke_certificate(
            cert.serial_number, x509.ReasonFlags.key_compromise
        )
        with pytest.raises(CertificateRevokedError):
            await mgr.cosign_certificate(cert, is_overwrite=True)

    def test_sync_cosign_without_db_still_works(self, tmp_path):
        factory = _factory(tmp_path)
        mgr = CertLifecycleManager(
            storage=LocalStorage(tmp_path / "certs"), factory=factory
        )
        cert, _, _ = factory.issue_certificate("svc", days_valid=1)
        assert mgr.cosign_certificate(cert).serial_number != cert.serial_number

    async def test_async_cosign_without_db_still_works(self, tmp_path):
        factory = _factory(tmp_path)
        mgr = AsyncCertLifecycleManager(
            storage=AsyncLocalStorage(tmp_path / "certs"), factory=factory
        )
        cert, _, _ = factory.issue_certificate("svc", days_valid=1)
        cosigned = await mgr.cosign_certificate(cert)
        assert cosigned.serial_number != cert.serial_number


# ---------------------------------------------------------------------------
# Deleting a revoked, unexpired certificate would drop it from the CRL
# ---------------------------------------------------------------------------


class TestDeleteRevoked:
    def test_sync_delete_of_revoked_is_refused(self, env):
        mgr, db = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        with pytest.raises(CertificateRevokedError):
            mgr.delete_certificate(cert.serial_number)
        assert db.get_by_serial(cert.serial_number) is not None
        crl = mgr.generate_crl()
        assert crl.get_revoked_certificate_by_serial_number(cert.serial_number)

    def test_sync_delete_of_valid_still_works(self, env):
        mgr, db = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        assert mgr.delete_certificate(cert.serial_number) is True
        assert db.get_by_serial(cert.serial_number) is None

    async def test_async_delete_of_revoked_is_refused(self, aenv):
        mgr, db = aenv
        cert, _, _ = await mgr.issue_certificate(ClientConfig(common_name="svc"))
        await mgr.revoke_certificate(
            cert.serial_number, x509.ReasonFlags.key_compromise
        )
        with pytest.raises(CertificateRevokedError):
            await mgr.delete_certificate(cert.serial_number)
        assert await db.get_by_serial(cert.serial_number) is not None


# ---------------------------------------------------------------------------
# CA lifetime: leaves never outlive the CA; an expired CA validates nothing
# ---------------------------------------------------------------------------


class TestCALifetime:
    def test_leaf_not_after_is_clamped_to_ca(self, tmp_path):
        factory = _factory(tmp_path, days_valid=30)
        ca_not_after = factory._ca.ca_cert.not_valid_after_utc
        leaf, _, _ = factory.issue_certificate("leaf", days_valid=365)
        assert leaf.not_valid_after_utc == ca_not_after
        inter, _ = factory.issue_intermediate_ca("Inter", key_size=2048, days_valid=365)
        assert inter.not_valid_after_utc == ca_not_after
        renewed = factory.renew_certificate(leaf, days_valid=365)
        assert renewed.not_valid_after_utc == ca_not_after

    def test_default_leaf_lifetime_fits_default_ca(self, tmp_path):
        factory = _factory(tmp_path)
        leaf, _, _ = factory.issue_certificate("leaf", days_valid=3650)
        assert leaf.not_valid_after_utc <= factory._ca.ca_cert.not_valid_after_utc

    def test_issuance_from_expired_ca_is_refused(self, tmp_path):
        factory = _factory(tmp_path)
        factory._ca._ca_cert, factory._ca._ca_key = _expired_ca()
        with pytest.raises(InvalidRangeTimeCertificate):
            factory.issue_certificate("leaf", days_valid=1)

    def test_validation_fails_once_ca_expired(self, tmp_path):
        factory = _factory(tmp_path)
        factory._ca._ca_cert, factory._ca._ca_key = _expired_ca()
        ca_cert, ca_key = factory._ca.ca_cert, factory._ca.ca_key
        leaf_key = generate_private_key(key_size=2048)
        now = datetime.datetime.now(datetime.UTC)
        signed = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "leaf")])
            )
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(ca_key, hashes.SHA256())
        )
        with pytest.raises(ValidationCertError, match="CA certificate"):
            factory.validate_cert(signed)
        with pytest.raises(ValidationCertError, match="CA certificate"):
            factory.validate_chain(signed)


# ---------------------------------------------------------------------------
# CA loader sanity checks
# ---------------------------------------------------------------------------


class TestCALoaderChecks:
    def test_mismatched_key_rejected(self, tmp_path):
        cert, _ = CertificateFactory.build_self_signed_ca(common_name="A")
        _, other_key = CertificateFactory.build_self_signed_ca(common_name="B")
        cert_path, key_path = _save_ca(tmp_path, cert, other_key)
        with pytest.raises(ErrorLoadCert, match="does not match"):
            CAFileLoader(cert_path, key_path)

    def test_leaf_certificate_rejected_as_ca(self, tmp_path):
        factory = _factory(tmp_path)
        leaf, leaf_key, _ = factory.issue_certificate("leaf", days_valid=1)
        cert_path, key_path = _save_ca(tmp_path / "leaf", leaf, leaf_key)
        with pytest.raises(ErrorLoadCert, match="not a CA"):
            CAFileLoader(cert_path, key_path)

    async def test_async_loader_applies_same_checks(self, tmp_path):
        cert, _ = CertificateFactory.build_self_signed_ca(common_name="A")
        _, other_key = CertificateFactory.build_self_signed_ca(common_name="B")
        cert_path, key_path = _save_ca(tmp_path, cert, other_key)
        with pytest.raises(ErrorLoadCert, match="does not match"):
            await AsyncCAFileLoader.create(cert_path, key_path)

    @staticmethod
    def _self_signed(tmp_path, *extensions):
        key = generate_private_key(key_size=2048)
        now = datetime.datetime.now(datetime.UTC)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "X")])
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
        )
        for ext in extensions:
            builder = builder.add_extension(ext, critical=True)
        return _save_ca(tmp_path, builder.sign(key, hashes.SHA256()), key)

    def test_certificate_without_basic_constraints_rejected(self, tmp_path):
        with pytest.raises(ErrorLoadCert, match="BasicConstraints"):
            CAFileLoader(*self._self_signed(tmp_path))

    def test_key_usage_without_cert_sign_rejected(self, tmp_path):
        usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        paths = self._self_signed(
            tmp_path, x509.BasicConstraints(ca=True, path_length=None), usage
        )
        with pytest.raises(ErrorLoadCert, match="keyCertSign"):
            CAFileLoader(*paths)

    def test_expired_ca_loads_with_warning(self, tmp_path, caplog):
        paths = _save_ca(tmp_path, *_expired_ca())
        with caplog.at_level("WARNING", logger="TinyCA"):
            loader = CAFileLoader(*paths)
        assert loader.ca_cert is not None
        assert any("expired" in r.getMessage() for r in caplog.records)

    def test_valid_ca_loads(self, tmp_path):
        factory = _factory(tmp_path)
        assert factory._ca.ca_cert is not None


# ---------------------------------------------------------------------------
# Private keys at rest
# ---------------------------------------------------------------------------


class TestKeyAtRest:
    def test_encrypted_rsa_key_uses_pkcs8_not_legacy_pem(self, tmp_path):
        key = generate_private_key(KeyAlgorithm.RSA, 2048)
        store = LocalStorage(
            tmp_path,
            base_encryption_algorithm=serialization.BestAvailableEncryption(b"pw"),
        )
        path, _ = store.save_certificate(key, "k", is_add_uuid=False)
        data = path.read_bytes()
        assert data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        assert b"DEK-Info" not in data
        loaded = serialization.load_pem_private_key(data, b"pw")
        assert loaded.private_numbers() == key.private_numbers()

    def test_unencrypted_rsa_key_keeps_configured_format(self, tmp_path):
        key = generate_private_key(KeyAlgorithm.RSA, 2048)
        path, _ = LocalStorage(tmp_path).save_certificate(key, "k", is_add_uuid=False)
        assert path.read_bytes().startswith(b"-----BEGIN RSA PRIVATE KEY-----")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions and symlinks")
class TestAtomicWrite:
    def test_overwrite_replaces_world_readable_file_with_0600(self, tmp_path):
        target = tmp_path / "ca.key"
        target.write_bytes(b"old")
        target.chmod(0o644)
        _write_bytes(target, b"new", is_overwrite=True, mode=0o600)
        assert target.read_bytes() == b"new"
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_overwrite_does_not_follow_symlink(self, tmp_path):
        victim = tmp_path / "victim"
        victim.write_bytes(b"untouched")
        link = tmp_path / "store" / "ca.key"
        link.parent.mkdir()
        link.symlink_to(victim)
        _write_bytes(link, b"secret", is_overwrite=True, mode=0o600)
        assert victim.read_bytes() == b"untouched"
        assert not link.is_symlink()
        assert link.read_bytes() == b"secret"

    def test_failed_replace_removes_temp_file(self, tmp_path, monkeypatch):
        target = tmp_path / "ca.key"
        target.write_bytes(b"old")

        def boom(*_args):
            raise OSError("disk full")

        monkeypatch.setattr(os, "replace", boom)
        with pytest.raises(OSError, match="disk full"):
            _write_bytes(target, b"new", is_overwrite=True, mode=0o600)
        assert [p.name for p in tmp_path.iterdir()] == ["ca.key"]
        assert target.read_bytes() == b"old"

    def test_falls_back_to_chmod_without_fchmod(self, tmp_path, monkeypatch):
        monkeypatch.delattr(os, "fchmod")
        target = tmp_path / "pub.pem"
        _write_bytes(target, b"x", is_overwrite=False, mode=0o640)
        assert stat.S_IMODE(target.stat().st_mode) == 0o640

    def test_no_temp_files_left_behind(self, tmp_path):
        target = tmp_path / "crl.pem"
        _write_bytes(target, b"a", is_overwrite=False, mode=0o644)
        _write_bytes(target, b"b", is_overwrite=True, mode=0o644)
        assert [p.name for p in tmp_path.iterdir()] == ["crl.pem"]
        assert stat.S_IMODE(target.stat().st_mode) == 0o644


# ---------------------------------------------------------------------------
# PKCS#12 password handling
# ---------------------------------------------------------------------------


class TestPKCS12Password:
    def test_empty_password_rejected(self, tmp_path):
        factory = _factory(tmp_path)
        cert, key, _ = factory.issue_certificate("p12", days_valid=1)
        with pytest.raises(ValueError, match="empty"):
            factory.export_pkcs12(cert, key, password=b"")

    def test_no_password_logs_warning(self, tmp_path, caplog):
        factory = _factory(tmp_path)
        cert, key, _ = factory.issue_certificate("p12", days_valid=1)
        caplog.clear()
        with caplog.at_level("WARNING", logger=factory._logger.name):
            factory.export_pkcs12(cert, key)
        assert any("PKCS#12" in r.getMessage() for r in caplog.records)
