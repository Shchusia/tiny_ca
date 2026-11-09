"""Tamper-evident audit log (1.0.0)."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import stat
import threading

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
import pytest
import pytest_asyncio

from tiny_ca import (
    AuditLog,
    CAConfig,
    CAFileLoader,
    CertificateFactory,
    CertLifecycleManager,
    ClientConfig,
    KeyAlgorithm,
    KeySigner,
    SyncDBHandler,
)
from tiny_ca.audit import GENESIS_HASH, _last_line, certificate_fields, crl_fields
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.exc import AuditLogError
from tiny_ca.managers.async_lifecycle_manager import AsyncCertLifecycleManager
from tiny_ca.storage import LocalStorage
from tiny_ca.storage.async_local_storage import AsyncLocalStorage
from tiny_ca.utils.keys import generate_private_key, signing_hash


@pytest.fixture
def log_path(tmp_path) -> Path:
    return tmp_path / "audit.jsonl"


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _rewrite(path: Path, entries: list[dict]) -> None:
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))


# ---------------------------------------------------------------------------
# Chain and signatures
# ---------------------------------------------------------------------------


def test_unsigned_chain(log_path):
    log = AuditLog(log_path, actor="alice")
    assert log.head == GENESIS_HASH
    first = log.record("a", {"x": 1})
    second = log.record("b", actor="bob")
    assert first["seq"] == 0 and first["prev"] == GENESIS_HASH
    assert second["seq"] == 1 and second["prev"] == first["hash"]
    assert second["actor"] == "bob" and first["actor"] == "alice"
    assert "sig" not in first
    assert log.head == second["hash"]
    assert AuditLog.verify(log_path, expected_head=log.head) == 2
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o640


def test_default_actor_and_non_json_values(log_path):
    when = datetime.datetime(2026, 1, 2, tzinfo=datetime.UTC)
    entry = AuditLog(log_path).record("e", {"when": when, "path": Path("/x")})
    assert entry["actor"]
    assert entry["data"] == {"when": str(when), "path": "/x"}
    assert AuditLog.verify(log_path) == 1


@pytest.mark.parametrize(
    "algorithm", [KeyAlgorithm.EC_P384, KeyAlgorithm.RSA, KeyAlgorithm.ED25519]
)
def test_signed_chain(log_path, algorithm):
    key = generate_private_key(algorithm)
    log = AuditLog(log_path, signer=key)
    for i in range(3):
        log.record("e", {"i": i})
    assert all("sig" in e for e in _lines(log_path))
    assert AuditLog.verify(log_path, public_key=key.public_key()) == 3


def test_external_signer_and_certificate_as_key(log_path):
    cert, key = CertificateFactory.build_self_signed_ca(common_name="Audit")
    AuditLog(log_path, signer=KeySigner(key)).record("e")
    assert AuditLog.verify(log_path, public_key=cert) == 1


def test_wrong_key_is_rejected(log_path):
    AuditLog(log_path, signer=generate_private_key()).record("e")
    other = generate_private_key().public_key()
    with pytest.raises(AuditLogError, match="invalid signature"):
        AuditLog.verify(log_path, public_key=other)


def test_missing_signature_is_rejected(log_path):
    AuditLog(log_path).record("e")
    with pytest.raises(AuditLogError, match="missing signature"):
        AuditLog.verify(log_path, public_key=generate_private_key().public_key())


def test_concurrent_writers_keep_the_chain(log_path):
    log = AuditLog(log_path)
    other = AuditLog(log_path)  # separate instance = separate thread lock

    def write(target, n):
        for i in range(n):
            target.record("e", {"i": i})

    threads = [
        threading.Thread(target=write, args=(t, 20)) for t in (log, other, log, other)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert AuditLog.verify(log_path) == 80


# ---------------------------------------------------------------------------
# Tampering
# ---------------------------------------------------------------------------


@pytest.fixture
def signed_log(log_path):
    key = ec.generate_private_key(ec.SECP384R1())
    log = AuditLog(log_path, signer=key)
    for i in range(4):
        log.record("e", {"i": i})
    return log_path, key.public_key(), log.head


def test_edited_entry(signed_log):
    path, public, _ = signed_log
    entries = _lines(path)
    entries[1]["data"]["i"] = 99
    _rewrite(path, entries)
    with pytest.raises(AuditLogError, match="seq=1.*does not match its hash"):
        AuditLog.verify(path)


def test_edited_entry_with_recomputed_hash_needs_the_key(signed_log):
    from tiny_ca.audit import _entry_hash

    path, public, _ = signed_log
    entries = _lines(path)
    entries[3]["data"]["i"] = 99
    entries[3]["hash"] = _entry_hash(entries[3])
    _rewrite(path, entries)
    assert AuditLog.verify(path) == 4  # the chain alone cannot tell
    with pytest.raises(AuditLogError, match="invalid signature"):
        AuditLog.verify(path, public_key=public)


def test_deleted_entry(signed_log):
    path, _, _ = signed_log
    entries = _lines(path)
    del entries[1]
    _rewrite(path, entries)
    with pytest.raises(AuditLogError, match="expected seq=1"):
        AuditLog.verify(path)


def test_broken_link(signed_log):
    path, _, _ = signed_log
    entries = _lines(path)
    entries[2]["prev"] = GENESIS_HASH
    _rewrite(path, entries)
    with pytest.raises(AuditLogError, match="chain broken"):
        AuditLog.verify(path)


def test_truncated_tail_detected_with_expected_head(signed_log):
    path, public, head = signed_log
    _rewrite(path, _lines(path)[:-1])
    assert AuditLog.verify(path, public_key=public) == 3
    with pytest.raises(AuditLogError, match="head"):
        AuditLog.verify(path, public_key=public, expected_head=head)


def test_garbage_line(signed_log):
    path, _, _ = signed_log
    with path.open("a") as f:
        f.write("\n{not json\n")
    with pytest.raises(AuditLogError, match="line 6: not valid JSON"):
        AuditLog.verify(path)


def test_refuses_to_append_after_corrupt_tail(log_path):
    log_path.write_text('{"seq": 0}\n')
    with pytest.raises(AuditLogError, match="corrupt"):
        AuditLog(log_path).record("e")


# ---------------------------------------------------------------------------
# Failures and helpers
# ---------------------------------------------------------------------------


def test_unwritable_path(tmp_path):
    with pytest.raises(AuditLogError, match="cannot write"):
        AuditLog(tmp_path).record("e")  # a directory


def test_failing_signer(log_path):
    class Broken:
        def public_key(self):
            return ed25519.Ed25519PrivateKey.generate().public_key()

        def sign(self, data, algorithm):
            raise RuntimeError("token removed")

    with pytest.raises(AuditLogError, match="token removed"):
        AuditLog(log_path, signer=Broken()).record("e")
    assert not log_path.read_bytes()


def test_last_line_reads_across_blocks(tmp_path):
    path = tmp_path / "f"
    big = b"x" * 10_000
    cases = {
        b"first\n" + big + b"\n\n": big,
        big + b"\n": big,
        b"a\n" + big: b"a",  # unterminated fragment is ignored
        big: None,
        b"\n\n": None,
        b"": None,
    }
    for content, expected in cases.items():
        path.write_bytes(content)
        with path.open("rb") as f:
            assert _last_line(f) == expected


@pytest.mark.parametrize("prefix_entries", [0, 3])
@pytest.mark.parametrize("fragment", [b'{"seq": 3, "ts', b"y" * 9000])
def test_torn_tail_is_cut_and_recorded(log_path, prefix_entries, fragment):
    key = generate_private_key()
    log = AuditLog(log_path, signer=key)
    for _ in range(prefix_entries):
        log.record("e")
    with log_path.open("ab") as f:
        f.write(fragment)
    entry = log.record("after")
    entries = list(AuditLog.entries(log_path))
    torn = entries[-2]
    assert torn["event"] == "audit.torn_entry_removed"
    assert torn["data"]["bytes"] == len(fragment)
    assert entry["seq"] == prefix_entries + 1
    assert AuditLog.verify(log_path, public_key=key.public_key()) == len(entries)


def test_head_ignores_torn_tail(log_path):
    log = AuditLog(log_path)
    log.record("e")
    head = log.head
    with log_path.open("ab") as f:
        f.write(b'{"partial')
    assert log.head == head


def test_non_ascii_and_lone_surrogates(log_path):
    log = AuditLog(log_path)
    log.record("e", {"cn": "Київ \ud800 ✓"})
    assert AuditLog.verify(log_path) == 1
    assert log_path.read_bytes().isascii()


def test_non_object_line(log_path):
    log_path.write_text("[]\n")
    with pytest.raises(AuditLogError, match="not a JSON object"):
        AuditLog.verify(log_path)


def test_crl_fields_without_number():
    cert, key = CertificateFactory.build_self_signed_ca(common_name="R")
    now = datetime.datetime.now(datetime.UTC)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .sign(key, signing_hash(key))
    )
    fields = crl_fields(crl)
    assert fields["crl_number"] is None
    assert fields["revoked"] == 0
    assert fields["issuer"] == cert.subject.rfc4514_string()
    assert fields["next_update"]


# ---------------------------------------------------------------------------
# Manager integration
# ---------------------------------------------------------------------------


def _factory(tmp: Path) -> CertificateFactory:
    cert, key = CertificateFactory.build_self_signed_ca(common_name="Root")
    store = LocalStorage(tmp / "ca")
    cert_path, _ = store.save_certificate(cert, "ca", is_add_uuid=False)
    key_path, _ = store.save_certificate(key, "ca", is_add_uuid=False)
    return CertificateFactory(CAFileLoader(cert_path, key_path))


def _foreign_cert(tmp: Path) -> x509.Certificate:
    other = _factory(tmp / "other")
    return other.issue_certificate("external", is_client_cert=True)[0]


EXPECTED_EVENTS = [
    "ca.created",
    "certificate.issued",
    "certificate.rotated",
    "certificate.renewed",
    "certificate.cosigned",
    "intermediate_ca.issued",
    "certificate.revoked",
    "certificate.revoke_failed",
    "crl.generated",
    "pkcs12.exported",
    "certificate.deleted",
]


def test_type_check():
    with pytest.raises(TypeError, match="audit_log"):
        CertLifecycleManager(audit_log="audit.jsonl")
    with pytest.raises(TypeError, match="audit_log"):
        AsyncCertLifecycleManager(audit_log="audit.jsonl")


def test_sync_manager_audits_every_operation(tmp_path):
    key = generate_private_key()
    audit = AuditLog(tmp_path / "audit.jsonl", signer=key, actor="ops")
    mgr = CertLifecycleManager(
        storage=LocalStorage(tmp_path / "certs"),
        db_handler=SyncDBHandler(db_url=f"sqlite:///{tmp_path}/ca.db"),
        factory=_factory(tmp_path),
        audit_log=audit,
    )
    mgr.create_self_signed_ca(CAConfig(common_name="Other Root"))
    cert, priv, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
    rotated, _, _ = mgr.rotate_certificate(
        cert.serial_number, ClientConfig(common_name="svc2")
    )
    renewed = mgr.renew_certificate(rotated.serial_number)
    mgr.cosign_certificate(_foreign_cert(tmp_path))
    mgr.issue_intermediate_ca("Sub")
    mgr.revoke_certificate(renewed.serial_number, x509.ReasonFlags.key_compromise)
    mgr.revoke_certificate(12345, x509.ReasonFlags.unspecified)
    mgr.generate_crl()
    mgr.export_pkcs12(cert, priv, password=b"secret")
    issued, _, _ = mgr.issue_certificate(ClientConfig(common_name="tmp"))
    assert mgr.delete_certificate(issued.serial_number)

    entries = list(AuditLog.entries(audit.path))
    assert sorted({e["event"] for e in entries}) == sorted(EXPECTED_EVENTS)
    assert {e["actor"] for e in entries} == {"ops"}
    assert AuditLog.verify(audit.path, public_key=key.public_key()) == len(entries)

    by_event = {e["event"]: e["data"] for e in entries}
    assert by_event["certificate.renewed"]["replaced_serial"] == str(
        rotated.serial_number
    )
    assert by_event["certificate.issued"]["sha256"]
    assert by_event["certificate.revoked"]["reason"] == "keyCompromise"
    assert by_event["pkcs12.exported"]["encrypted"] is True
    assert by_event["crl.generated"]["revoked"] >= 1
    assert by_event["certificate.deleted"]["deleted"] is True


@pytest_asyncio.fixture
async def adb(tmp_path):
    db = AsyncDBHandler(db_url=f"sqlite+aiosqlite:///{tmp_path}/ca.db")
    await db._db.init_db()
    yield db
    await db._db.engine.dispose()


async def test_async_manager_audits_every_operation(tmp_path, adb):
    audit = AuditLog(tmp_path / "audit.jsonl")
    mgr = AsyncCertLifecycleManager(
        storage=AsyncLocalStorage(tmp_path / "certs"),
        db_handler=adb,
        factory=_factory(tmp_path),
        audit_log=audit,
    )
    await mgr.create_self_signed_ca(CAConfig(common_name="Other Root"))
    cert, priv, _ = await mgr.issue_certificate(ClientConfig(common_name="svc"))
    rotated, _, _ = await mgr.rotate_certificate(
        cert.serial_number, ClientConfig(common_name="svc2")
    )
    renewed = await mgr.renew_certificate(rotated.serial_number)
    await mgr.cosign_certificate(_foreign_cert(tmp_path))
    await mgr.issue_intermediate_ca("Sub")
    await mgr.revoke_certificate(renewed.serial_number, x509.ReasonFlags.key_compromise)
    await mgr.revoke_certificate(12345, x509.ReasonFlags.unspecified)
    await mgr.generate_crl()
    await mgr.export_pkcs12(cert, priv)
    issued, _, _ = await mgr.issue_certificate(ClientConfig(common_name="tmp"))
    assert await mgr.delete_certificate(issued.serial_number)

    events = {e["event"] for e in AuditLog.entries(audit.path)}
    assert sorted(events) == sorted(EXPECTED_EVENTS)
    assert AuditLog.verify(audit.path) == 12


def test_certificate_fields():
    cert, _ = CertificateFactory.build_self_signed_ca(common_name="R")
    fields = certificate_fields(cert)
    assert fields["serial"] == str(cert.serial_number)
    assert fields["subject"] == fields["issuer"] == cert.subject.rfc4514_string()
    assert len(fields["sha256"]) == 64
