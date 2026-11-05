"""
Async counterparts of ``test_review_regressions.py`` — real aiosqlite
database and real filesystem, no mocks for the code paths under test.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path
import stat
from unittest.mock import AsyncMock, patch

from cryptography import x509
import pytest
import pytest_asyncio
from sqlalchemy import update

from tiny_ca import (
    CAFileLoader,
    CertificateFactory,
    CertType,
    ClientConfig,
    KeyAlgorithm,
)
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.db.const import CertificateStatus, RevokeStatus
from tiny_ca.db.models import CertificateRecord
from tiny_ca.db.utils import utc_naive
from tiny_ca.exc import (
    CertRevocationError,
    DBOperationError,
    NotUniqueCertOwner,
    ValidationCertError,
)
from tiny_ca.managers.async_lifecycle_manager import AsyncCertLifecycleManager
from tiny_ca.models.certificate import CAConfig
from tiny_ca.storage import LocalStorage
from tiny_ca.storage.async_local_storage import AsyncLocalStorage


def _factory(
    tmp: Path, algorithm: KeyAlgorithm = KeyAlgorithm.RSA
) -> CertificateFactory:
    cert, key = CertificateFactory.build_self_signed_ca(
        common_name="Root", key_algorithm=algorithm
    )
    store = LocalStorage(tmp / "ca")
    cert_path, _ = store.save_certificate(cert, "ca", is_add_uuid=False)
    key_path, _ = store.save_certificate(key, "ca", is_add_uuid=False)
    return CertificateFactory(CAFileLoader(cert_path, key_path))


@pytest_asyncio.fixture
async def env(tmp_path):
    db = AsyncDBHandler(db_url=f"sqlite+aiosqlite:///{tmp_path}/ca.db")
    await db._db.init_db()
    mgr = AsyncCertLifecycleManager(
        storage=AsyncLocalStorage(tmp_path / "certs"),
        db_handler=db,
        factory=_factory(tmp_path),
    )
    yield mgr, db, tmp_path
    await db._db.engine.dispose()


async def _record(db: AsyncDBHandler, serial: int) -> CertificateRecord:
    record = await db.get_by_serial(serial)
    assert record is not None
    return record


@pytest.mark.asyncio
async def test_old_revocation_stays_in_crl(env):
    mgr, db, _ = env
    cert, _, _ = await mgr.issue_certificate(
        ClientConfig(common_name="long", days_valid=1000)
    )
    await mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
    async with db._db.get_session() as session:
        await session.execute(
            update(CertificateRecord)
            .where(CertificateRecord.serial_number == str(cert.serial_number))
            .values(
                revocation_date=utc_naive(
                    datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=400)
                )
            )
        )
        await session.commit()

    crl = await mgr.generate_crl()
    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    assert entry is not None
    assert (
        entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
        == x509.ReasonFlags.key_compromise
    )
    await mgr.verify_crl(crl)


@pytest.mark.asyncio
async def test_fail_closed_when_db_is_down(env):
    mgr, db, tmp = env
    cert, _, _ = await mgr.issue_certificate(ClientConfig(common_name="svc"))
    await mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
    await db._db.engine.dispose()
    os.remove(tmp / "ca.db")
    (tmp / "ca.db").mkdir()

    with pytest.raises(DBOperationError):
        await mgr.verify_certificate(cert)
    with pytest.raises(DBOperationError):
        await mgr.generate_crl()
    with pytest.raises(DBOperationError):
        await mgr.list_certificates()
    assert not (tmp / "certs" / "crl.pem").exists()


@pytest.mark.asyncio
async def test_unregistered_certificate_rejected(env):
    mgr, _, _ = env
    cert, _, _ = mgr.factory.issue_certificate("stranger")
    with pytest.raises(ValidationCertError, match="not registered"):
        await mgr.verify_certificate(cert)


@pytest.mark.asyncio
async def test_duplicate_cn_writes_nothing(env):
    mgr, _, tmp = env
    await mgr.issue_certificate(ClientConfig(common_name="svc"))
    before = list((tmp / "certs").rglob("*"))
    with pytest.raises(NotUniqueCertOwner):
        await mgr.issue_certificate(ClientConfig(common_name="svc"))
    assert list((tmp / "certs").rglob("*")) == before


@pytest.mark.asyncio
async def test_register_failure_cleans_up(env):
    mgr, db, tmp = env
    with (
        patch.object(db, "register_cert_in_db", AsyncMock(return_value=False)),
        pytest.raises(DBOperationError),
    ):
        await mgr.issue_certificate(ClientConfig(common_name="svc"))
    assert list((tmp / "certs").rglob("*.key")) == []


@pytest.mark.asyncio
async def test_failed_save_into_user_folder_removes_only_written_files(env):
    mgr, _, tmp = env
    folder = tmp / "certs" / "fixed"
    folder.mkdir(parents=True)
    (folder / "svc.csr").write_text("existing")
    with pytest.raises(Exception, match="already exists"):
        await mgr.issue_certificate(ClientConfig(common_name="svc"), uuid_str="fixed")
    assert [p.name for p in folder.iterdir()] == ["svc.csr"]


@pytest.mark.asyncio
async def test_overwrite_and_key_permissions(env):
    mgr, db, tmp = env
    old, _, _ = await mgr.issue_certificate(ClientConfig(common_name="svc"))
    old_uuid = (await _record(db, old.serial_number)).uuid
    new, _, _ = await mgr.issue_certificate(
        ClientConfig(common_name="svc"), is_overwrite=True
    )
    old_rec = await _record(db, old.serial_number)
    assert old_rec.revocation_reason == x509.ReasonFlags.superseded.value
    assert not (tmp / "certs" / old_uuid).exists()

    folder = tmp / "certs" / (await _record(db, new.serial_number)).uuid
    assert stat.S_IMODE((folder / "svc.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((folder / "svc.pem").stat().st_mode) == 0o644


@pytest.mark.asyncio
async def test_renew_cosign_and_intermediate_are_registered(env, tmp_path):
    mgr, db, _ = env
    original, _, _ = await mgr.issue_certificate(
        ClientConfig(common_name="dev", serial_type=CertType.DEVICE)
    )
    renewed = await mgr.renew_certificate(original.serial_number, days_valid=30)
    assert (await _record(db, renewed.serial_number)).key_type == "DEV"
    assert (
        await _record(db, original.serial_number)
    ).status == CertificateStatus.REVOKED
    assert await mgr.verify_certificate(renewed)

    foreign = _factory(tmp_path / "foreign")
    third_party, _, _ = foreign.issue_certificate("partner")
    cosigned = await mgr.cosign_certificate(third_party)
    assert await mgr.verify_certificate(cosigned)

    inter_cert, inter_key = await mgr.issue_intermediate_ca("Inter", key_size=2048)
    assert (await _record(db, inter_cert.serial_number)).key_type == "CA"
    with pytest.raises(NotUniqueCertOwner):
        await mgr.issue_intermediate_ca("Inter", key_size=2048)

    class _Loader:
        ca_cert, ca_key, base_info = inter_cert, inter_key, mgr.factory._ca.base_info

    leaf, _, _ = CertificateFactory(_Loader()).issue_certificate("leaf")
    assert await mgr.verify_certificate(leaf, intermediates=[inter_cert])
    await mgr.revoke_certificate(
        inter_cert.serial_number, x509.ReasonFlags.ca_compromise
    )
    with pytest.raises(ValidationCertError, match="revoked"):
        await mgr.verify_certificate(leaf, intermediates=[inter_cert])


@pytest.mark.asyncio
async def test_rotation_rollback_and_conflicts(env):
    mgr, db, tmp = env
    a, _, _ = await mgr.issue_certificate(ClientConfig(common_name="a"))
    await mgr.issue_certificate(ClientConfig(common_name="b"))

    with pytest.raises(NotUniqueCertOwner):
        await mgr.rotate_certificate(a.serial_number, ClientConfig(common_name="b"))

    with (
        patch.object(
            db,
            "revoke_certificate",
            AsyncMock(return_value=(False, RevokeStatus.UNKNOWN_ERROR)),
        ),
        pytest.raises(CertRevocationError),
    ):
        await mgr.rotate_certificate(a.serial_number, ClientConfig(common_name="a"))
    assert len(await db.list_all()) == 2
    assert len(list((tmp / "certs").rglob("*.key"))) == 2

    new, _, _ = await mgr.rotate_certificate(
        a.serial_number, ClientConfig(common_name="a")
    )
    assert (await _record(db, a.serial_number)).status == CertificateStatus.REVOKED
    assert await mgr.verify_certificate(new)


@pytest.mark.asyncio
async def test_create_ca_and_ec_issuance(tmp_path):
    db = AsyncDBHandler(db_url=f"sqlite+aiosqlite:///{tmp_path}/ca.db")
    await db._db.init_db()
    mgr = AsyncCertLifecycleManager(
        storage=AsyncLocalStorage(tmp_path / "certs"),
        db_handler=db,
        factory=_factory(tmp_path, KeyAlgorithm.EC_P256),
    )
    cert_path, key_path = await mgr.create_self_signed_ca(
        CAConfig(common_name="Second Root", key_algorithm=KeyAlgorithm.ED25519)
    )
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    with pytest.raises(NotUniqueCertOwner):
        await mgr.create_self_signed_ca(CAConfig(common_name="Second Root"))

    cert, _, _ = await mgr.issue_certificate(
        ClientConfig(common_name="ec", key_algorithm=KeyAlgorithm.EC_P256)
    )
    assert await mgr.verify_certificate(cert)
    await db._db.engine.dispose()


@pytest.mark.asyncio
async def test_failure_before_any_write(env):
    mgr, _, _ = env
    from tiny_ca.exc import InvalidPathError

    with pytest.raises(InvalidPathError):
        await mgr.issue_certificate(ClientConfig(common_name="svc"), cert_path="/etc")
