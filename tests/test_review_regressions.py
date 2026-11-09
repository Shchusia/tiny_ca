"""
End-to-end regression tests for the issues found in the 0.2.x review.

Everything here runs against a real SQLite database and a real temporary
directory — no mocks for the code paths under test — so the tests check the
security-relevant *behaviour*, not just that lines execute.
"""

from __future__ import annotations

import datetime
import logging
import os
from pathlib import Path
import stat
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID
from pydantic import ValidationError
import pytest
from sqlalchemy import update

from tiny_ca import (
    CAFileLoader,
    CertificateFactory,
    CertLifecycleManager,
    CertType,
    ClientConfig,
    KeyAlgorithm,
    SyncDBHandler,
)
from tiny_ca.db.const import CertificateStatus, RevokeStatus
from tiny_ca.db.models import CertificateRecord
from tiny_ca.db.utils import certificate_common_name, utc_naive
from tiny_ca.exc import (
    CertRevocationError,
    DBOperationError,
    InvalidPathError,
    NotUniqueCertOwner,
    ValidationCertError,
)
from tiny_ca.managers.sync_lifecycle_manager import (
    cert_type_from_record,
    safe_file_name,
)
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.storage import LocalStorage
from tiny_ca.storage.local_storage import _CertSerializer
from tiny_ca.utils.keys import generate_private_key, public_key_info, signing_hash
from tiny_ca.utils.serial_generator import SerialWithEncoding

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_ca(tmp: Path, algorithm: KeyAlgorithm = KeyAlgorithm.RSA, **factory_kw):
    cert, key = CertificateFactory.build_self_signed_ca(
        common_name="Root", key_algorithm=algorithm
    )
    store = LocalStorage(tmp / "ca")
    cert_path, _ = store.save_certificate(cert, "ca", is_add_uuid=False)
    key_path, _ = store.save_certificate(key, "ca", is_add_uuid=False)
    return CertificateFactory(CAFileLoader(cert_path, key_path), **factory_kw)


@pytest.fixture
def env(tmp_path):
    db = SyncDBHandler(db_url=f"sqlite:///{tmp_path}/ca.db")
    mgr = CertLifecycleManager(
        storage=LocalStorage(tmp_path / "certs"),
        db_handler=db,
        factory=_write_ca(tmp_path),
    )
    return mgr, db, tmp_path


def _set_revocation_date(db: SyncDBHandler, serial: int, days_ago: int) -> None:
    session = db._db.session()
    try:
        session.execute(
            update(CertificateRecord)
            .where(CertificateRecord.serial_number == str(serial))
            .values(
                revocation_date=utc_naive(
                    datetime.datetime.now(datetime.UTC)
                    - datetime.timedelta(days=days_ago)
                )
            )
        )
        session.commit()
    finally:
        session.close()


def _record(db: SyncDBHandler, serial: int) -> CertificateRecord:
    record = db.get_by_serial(serial)
    assert record is not None
    return record


def _key_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.key"))


# ---------------------------------------------------------------------------
# CRL content
# ---------------------------------------------------------------------------


class TestCRL:
    def test_old_revocation_of_valid_cert_stays_in_crl(self, env):
        mgr, db, _ = env
        cert, _, _ = mgr.issue_certificate(
            ClientConfig(common_name="long", days_valid=1000)
        )
        mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        _set_revocation_date(db, cert.serial_number, days_ago=400)

        crl = mgr.generate_crl()
        assert crl.get_revoked_certificate_by_serial_number(cert.serial_number)

    def test_crl_has_number_aki_and_reason(self, env):
        mgr, _, _ = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="r1"))
        other, _, _ = mgr.issue_certificate(ClientConfig(common_name="r2"))
        mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        mgr.revoke_certificate(other.serial_number, x509.ReasonFlags.unspecified)

        crl = mgr.generate_crl(crl_number=42)
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value
        assert number.crl_number == 42
        crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)

        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        reason = entry.extensions.get_extension_for_class(x509.CRLReason).value
        assert reason.reason == x509.ReasonFlags.key_compromise

        unspecified = crl.get_revoked_certificate_by_serial_number(other.serial_number)
        assert len(unspecified.extensions) == 0  # RFC 5280: omit "unspecified"

    def test_default_crl_numbers_increase(self, env):
        mgr, _, _ = env
        first = mgr.generate_crl().extensions.get_extension_for_class(x509.CRLNumber)
        second = mgr.generate_crl().extensions.get_extension_for_class(x509.CRLNumber)
        assert second.value.crl_number > first.value.crl_number

    def test_unknown_reason_values_are_ignored(self, env):
        mgr, _, _ = env
        now = datetime.datetime.now(datetime.UTC)
        crl = mgr.factory.build_crl([(1, now, "garbage"), (2, now)])
        assert len(list(crl)) == 2

    def test_verify_crl_rejects_foreign_signature(self, env, tmp_path):
        mgr, _, _ = env
        # Same Subject, different key: issuer name matches but signature does not.
        impostor = _write_ca(tmp_path / "impostor")
        forged = impostor.build_crl([])
        with pytest.raises(ValidationCertError, match="signature"):
            mgr.verify_crl(forged)
        mgr.verify_crl(mgr.generate_crl())


# ---------------------------------------------------------------------------
# Fail-closed database handling
# ---------------------------------------------------------------------------


class TestFailClosed:
    def _break_db(self, db: SyncDBHandler, tmp: Path) -> None:
        db._db._engine.dispose()
        os.remove(tmp / "ca.db")
        (tmp / "ca.db").mkdir()  # SQLite cannot open a directory

    def test_verify_raises_when_db_is_down(self, env):
        mgr, db, tmp = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        self._break_db(db, tmp)
        with pytest.raises(DBOperationError):
            mgr.verify_certificate(cert)

    def test_no_crl_when_db_is_down(self, env):
        mgr, db, tmp = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        good = mgr.generate_crl()
        crl_file = tmp / "certs" / "crl.pem"
        before = crl_file.read_bytes()

        self._break_db(db, tmp)
        with pytest.raises(DBOperationError):
            mgr.generate_crl()
        assert crl_file.read_bytes() == before  # last good CRL untouched
        assert len(list(good)) == 1

    def test_unregistered_certificate_is_rejected(self, env):
        mgr, _, _ = env
        cert, _, _ = mgr.factory.issue_certificate("not-in-db")
        with pytest.raises(ValidationCertError, match="not registered"):
            mgr.verify_certificate(cert)

    def test_register_failure_removes_artefacts(self, env):
        mgr, db, tmp = env
        with (
            patch.object(db, "register_cert_in_db", return_value=False),
            pytest.raises(DBOperationError, match="register_cert_in_db"),
        ):
            mgr.issue_certificate(ClientConfig(common_name="svc"))
        assert _key_files(tmp / "certs") == []


# ---------------------------------------------------------------------------
# Every CA-signed certificate is registered
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_renewed_certificate_is_registered_and_revocable(self, env):
        mgr, db, _ = env
        original, _, _ = mgr.issue_certificate(
            ClientConfig(common_name="dev1", serial_type=CertType.DEVICE)
        )
        renewed = mgr.renew_certificate(original.serial_number, days_valid=30)

        assert renewed.public_key() == original.public_key()
        assert SerialWithEncoding.parse(renewed.serial_number)[0] is CertType.DEVICE
        record = _record(db, renewed.serial_number)
        assert record.key_type == CertType.DEVICE.value
        old = _record(db, original.serial_number)
        assert old.status == CertificateStatus.REVOKED
        assert old.revocation_reason == x509.ReasonFlags.superseded.value

        assert mgr.verify_certificate(renewed)
        assert mgr.revoke_certificate(
            renewed.serial_number, x509.ReasonFlags.key_compromise
        )
        with pytest.raises(ValidationCertError, match="revoked"):
            mgr.verify_certificate(renewed)

    def test_cosigned_certificate_is_registered(self, env, tmp_path):
        mgr, db, _ = env
        foreign = _write_ca(tmp_path / "foreign")
        third_party, _, _ = foreign.issue_certificate("partner.example")
        cosigned = mgr.cosign_certificate(third_party, days_valid=10)
        assert _record(db, cosigned.serial_number).common_name == "partner.example"
        assert mgr.verify_certificate(cosigned)
        with pytest.raises(NotUniqueCertOwner):
            mgr.cosign_certificate(third_party)

    def test_cosign_without_cn_uses_subject(self, env):
        mgr, db, _ = env
        key = generate_private_key()
        now = datetime.datetime.now(datetime.UTC)
        name = x509.Name([x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "NoCN")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=5))
            .sign(key, signing_hash(key))
        )
        cosigned = mgr.cosign_certificate(cert)
        assert _record(db, cosigned.serial_number).common_name == "O=NoCN"

    def test_intermediate_is_registered_in_one_folder_and_revocable(self, env):
        mgr, db, tmp = env
        inter, _ = mgr.issue_intermediate_ca("Issuing CA", key_size=2048)
        record = _record(db, inter.serial_number)
        assert record.key_type == CertType.CA.value
        folder = tmp / "certs" / record.uuid
        assert {p.name for p in folder.iterdir()} == {
            "intermediate_ca.pem",
            "intermediate_ca.key",
        }
        with pytest.raises(NotUniqueCertOwner):
            mgr.issue_intermediate_ca("Issuing CA", key_size=2048)

        mgr.revoke_certificate(inter.serial_number, x509.ReasonFlags.ca_compromise)
        crl = mgr.generate_crl()
        assert crl.get_revoked_certificate_by_serial_number(inter.serial_number)

    def test_registered_dates_are_naive_utc(self, env):
        mgr, db, _ = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        record = _record(db, cert.serial_number)
        assert record.not_valid_after.tzinfo is None
        assert record.not_valid_after == utc_naive(cert.not_valid_after_utc)


# ---------------------------------------------------------------------------
# Issuance consistency, overwrite and rotation
# ---------------------------------------------------------------------------


class TestIssuanceConsistency:
    def test_duplicate_cn_writes_nothing(self, env):
        mgr, _, tmp = env
        mgr.issue_certificate(ClientConfig(common_name="svc"))
        before = list((tmp / "certs").rglob("*"))
        with pytest.raises(NotUniqueCertOwner):
            mgr.issue_certificate(ClientConfig(common_name="svc"))
        assert list((tmp / "certs").rglob("*")) == before

    def test_overwrite_supersedes_and_removes_old_folder(self, env):
        mgr, db, tmp = env
        old, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        old_uuid = _record(db, old.serial_number).uuid
        new, _, _ = mgr.issue_certificate(
            ClientConfig(common_name="svc"), is_overwrite=True
        )
        old_rec = _record(db, old.serial_number)
        assert old_rec.revocation_reason == x509.ReasonFlags.superseded.value
        assert not (tmp / "certs" / old_uuid).exists()
        assert db.get_by_name("svc").serial_number == str(new.serial_number)

    def test_rotation_rolls_back_when_old_cert_cannot_be_revoked(self, env):
        mgr, db, tmp = env
        old, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        with (
            patch.object(
                db,
                "revoke_certificate",
                return_value=(False, RevokeStatus.UNKNOWN_ERROR),
            ),
            pytest.raises(CertRevocationError),
        ):
            mgr.rotate_certificate(old.serial_number, ClientConfig(common_name="svc"))
        assert len(db.list_all()) == 1
        assert _record(db, old.serial_number).status == CertificateStatus.VALID
        assert len(_key_files(tmp / "certs")) == 1

    def test_rotation_does_not_revoke_unrelated_cert(self, env):
        mgr, db, _ = env
        a, _, _ = mgr.issue_certificate(ClientConfig(common_name="a"))
        b, _, _ = mgr.issue_certificate(ClientConfig(common_name="b"))
        with pytest.raises(NotUniqueCertOwner):
            mgr.rotate_certificate(a.serial_number, ClientConfig(common_name="b"))
        assert _record(db, a.serial_number).status == CertificateStatus.VALID
        assert _record(db, b.serial_number).status == CertificateStatus.VALID

    def test_rotation_supersedes_old(self, env):
        mgr, db, _ = env
        old, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        new, _, _ = mgr.rotate_certificate(
            old.serial_number, ClientConfig(common_name="svc")
        )
        assert _record(db, old.serial_number).status == CertificateStatus.REVOKED
        assert mgr.verify_certificate(new)

    def test_failed_save_into_user_folder_removes_only_written_files(self, env):
        mgr, _, tmp = env
        folder = tmp / "certs" / "fixed"
        folder.mkdir(parents=True)
        (folder / "keep.txt").write_text("x")
        (folder / "svc.csr").write_text("existing")  # 3rd artefact collides
        with pytest.raises(Exception, match="already exists"):
            mgr.issue_certificate(ClientConfig(common_name="svc"), uuid_str="fixed")
        assert sorted(p.name for p in folder.iterdir()) == ["keep.txt", "svc.csr"]

    def test_default_storage_is_per_instance(self):
        assert CertLifecycleManager()._storage is not CertLifecycleManager()._storage


# ---------------------------------------------------------------------------
# Storage safety
# ---------------------------------------------------------------------------


class TestStorageSafety:
    def test_key_permissions(self, env):
        mgr, db, tmp = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        folder = tmp / "certs" / _record(db, cert.serial_number).uuid
        assert stat.S_IMODE((folder / "svc.key").stat().st_mode) == 0o600
        assert stat.S_IMODE((folder / "svc.pem").stat().st_mode) == 0o644

    def test_overwrite_tightens_existing_key_permissions(self, tmp_path):
        store = LocalStorage(tmp_path)
        target = tmp_path / "k.key"
        target.write_bytes(b"old")
        target.chmod(0o644)
        store.save_certificate(
            generate_private_key(), "k", is_add_uuid=False, is_overwrite=True
        )
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_plaintext_key_warning_logged_once(self, tmp_path, caplog):
        store = LocalStorage(tmp_path)
        with caplog.at_level(logging.WARNING, logger="TinyCA"):
            store.save_certificate(generate_private_key(), "a")
            store.save_certificate(generate_private_key(), "b")
        assert sum("unencrypted" in r.message for r in caplog.records) == 1

    def test_encrypted_key(self, tmp_path):
        store = LocalStorage(
            tmp_path,
            base_encryption_algorithm=serialization.BestAvailableEncryption(b"pw"),
        )
        path, _ = store.save_certificate(generate_private_key(), "k")
        assert b"ENCRYPTED" in path.read_bytes()

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"file_name": "../evil"},
            {"file_name": "a/b"},
            {"file_name": "a\\b"},
            {"file_name": ""},
            {"file_name": "x", "uuid_str": "../.."},
            {"file_name": "x", "cert_path": "/etc"},
            {"file_name": "x", "cert_path": "a/../../b"},
        ],
    )
    def test_path_traversal_rejected(self, tmp_path, kwargs):
        store = LocalStorage(tmp_path / "root")
        cert, _ = CertificateFactory.build_self_signed_ca()
        with pytest.raises(InvalidPathError):
            store.save_certificate(cert, **kwargs)

    def test_nested_cert_path_allowed(self, tmp_path):
        store = LocalStorage(tmp_path)
        cert, _ = CertificateFactory.build_self_signed_ca()
        path, _ = store.save_certificate(cert, "ca", cert_path="tenants/a")
        assert path.is_relative_to(tmp_path / "tenants" / "a")

    def test_delete_rejects_traversal(self, tmp_path):
        with pytest.raises(InvalidPathError):
            LocalStorage(tmp_path).delete_certificate_folder("../outside")

    @pytest.mark.parametrize("name", ["../x", "a/b", ".hidden", "a b"])
    def test_client_config_rejects_unsafe_name(self, name):
        with pytest.raises(ValidationError):
            ClientConfig(common_name="svc", name=name)

    def test_safe_file_name_from_cn(self):
        assert safe_file_name("../Etc/Passwd") == "_etc_passwd"
        assert safe_file_name("...") == "cert"
        assert safe_file_name("Сервер Дрон") == "сервер дрон"

    def test_serializer_rejects_unknown_type(self):
        with pytest.raises(TypeError):
            _CertSerializer.serialise(
                object(),  # type: ignore[arg-type]
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.PublicFormat.SubjectPublicKeyInfo,
                serialization.NoEncryption(),
            )

    @pytest.mark.parametrize("algorithm", list(KeyAlgorithm))
    def test_all_key_types_round_trip(self, tmp_path, algorithm):
        store = LocalStorage(
            tmp_path, base_public_format=serialization.PublicFormat.PKCS1
        )
        key = generate_private_key(algorithm)
        key_path, uuid = store.save_certificate(key, "k")
        pub_path, _ = store.save_certificate(key.public_key(), "k", uuid_str=uuid)
        loaded = serialization.load_pem_private_key(key_path.read_bytes(), None)
        assert loaded.public_key() == key.public_key()
        assert pub_path.read_bytes().startswith(b"-----BEGIN")


# ---------------------------------------------------------------------------
# Certificate contents and algorithms
# ---------------------------------------------------------------------------


class TestCertificateContents:
    def test_san_is_non_critical(self, env):
        mgr, _, _ = env
        cert, _, _ = mgr.issue_certificate(
            ClientConfig(common_name="web", san_dns=["web", "alt"], san_ip=["10.0.0.1"])
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san.critical is False
        assert san.value.get_values_for_type(x509.DNSName) == ["web", "alt"]

    def test_distribution_points_and_aia(self, tmp_path):
        factory = _write_ca(
            tmp_path,
            crl_distribution_points=["http://pki.test/crl.pem"],
            ca_issuers_urls=["http://pki.test/ca.pem"],
            ocsp_urls=["http://ocsp.pki.test"],
        )
        leaf, _, _ = factory.issue_certificate("svc")
        inter, _ = factory.issue_intermediate_ca("Inter", key_size=2048)
        for cert in (leaf, inter):
            cdp = cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            ).value
            assert cdp[0].full_name[0].value == "http://pki.test/crl.pem"
            aia = cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            ).value
            assert len(aia) == 2

    def test_cosign_replaces_foreign_distribution_points(self, tmp_path):
        foreign = _write_ca(
            tmp_path / "foreign", crl_distribution_points=["http://foreign/crl"]
        )
        ours = _write_ca(tmp_path / "ours", crl_distribution_points=["http://ours/crl"])
        third_party, _, _ = foreign.issue_certificate("p")
        cosigned = ours.cosign_certificate(third_party)
        cdp = cosigned.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        assert cdp.value[0].full_name[0].value == "http://ours/crl"
        ours.validate_cert(cosigned)

    @pytest.mark.parametrize(
        "algorithm,key_type",
        [
            (KeyAlgorithm.EC_P256, ec.EllipticCurvePrivateKey),
            (KeyAlgorithm.EC_P384, ec.EllipticCurvePrivateKey),
            (KeyAlgorithm.ED25519, ed25519.Ed25519PrivateKey),
        ],
    )
    def test_non_rsa_ca_and_leaf(self, tmp_path, algorithm, key_type):
        db = SyncDBHandler(db_url=f"sqlite:///{tmp_path}/ca.db")
        mgr = CertLifecycleManager(
            storage=LocalStorage(tmp_path / "certs"),
            db_handler=db,
            factory=_write_ca(tmp_path, algorithm),
        )
        cert, key, csr = mgr.issue_certificate(
            ClientConfig(common_name="svc", key_algorithm=algorithm)
        )
        assert isinstance(key, key_type)
        assert csr.is_signature_valid
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.digital_signature and not ku.key_encipherment
        assert mgr.verify_certificate(cert)
        mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        mgr.verify_crl(mgr.generate_crl())
        assert mgr.export_pkcs12(cert, key, password=b"pw")

    def test_rsa_leaf_keeps_key_encipherment(self, env):
        mgr, _, _ = env
        cert, _, _ = mgr.issue_certificate(
            ClientConfig(common_name="svc", key_algorithm=KeyAlgorithm.RSA)
        )
        assert cert.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value.key_encipherment

    def test_small_rsa_key_rejected(self):
        with pytest.raises(ValueError):
            generate_private_key(KeyAlgorithm.RSA, 1024)
        with pytest.raises(ValidationError):
            ClientConfig(common_name="x", key_size=1024)

    def test_public_key_info(self):
        assert public_key_info(
            generate_private_key(KeyAlgorithm.RSA, 2048).public_key()
        ) == ("rsa", 2048)
        assert public_key_info(generate_private_key().public_key()) == (
            "ec-secp384r1",
            384,
        )
        assert public_key_info(
            generate_private_key(KeyAlgorithm.ED25519).public_key()
        ) == ("ed25519", 256)
        assert public_key_info(object()) == (None, None)


# ---------------------------------------------------------------------------
# Chain validation
# ---------------------------------------------------------------------------


class _Loader:
    def __init__(self, cert, key, base_info):
        self.ca_cert, self.ca_key, self.base_info = cert, key, base_info


class TestChainValidation:
    def _chain(self, tmp_path, path_length=0):
        root = _write_ca(tmp_path)
        inter_cert, inter_key = root.issue_intermediate_ca(
            "Inter", key_size=2048, path_length=path_length
        )
        inter = CertificateFactory(_Loader(inter_cert, inter_key, root._ca.base_info))
        return root, inter, inter_cert

    def test_leaf_via_intermediate(self, tmp_path):
        root, inter, inter_cert = self._chain(tmp_path)
        leaf, _, _ = inter.issue_certificate("leaf")
        path = root.validate_chain(leaf, [inter_cert])
        assert [c.subject for c in path] == [
            leaf.subject,
            inter_cert.subject,
            root._ca.ca_cert.subject,
        ]
        with pytest.raises(ValidationCertError, match="issuer"):
            root.validate_cert(leaf)

    def test_missing_intermediate(self, tmp_path):
        root, inter, _ = self._chain(tmp_path)
        leaf, _, _ = inter.issue_certificate("leaf")
        with pytest.raises(ValidationCertError, match="No issuer"):
            root.validate_chain(leaf, [])

    def test_path_length_enforced(self, tmp_path):
        root, inter, inter_cert = self._chain(tmp_path, path_length=0)
        sub_cert, sub_key = inter.issue_intermediate_ca("Sub", key_size=2048)
        sub = CertificateFactory(_Loader(sub_cert, sub_key, root._ca.base_info))
        leaf, _, _ = sub.issue_certificate("leaf")
        with pytest.raises(ValidationCertError, match="Path length"):
            root.validate_chain(leaf, [sub_cert, inter_cert])

    def test_leaf_cannot_act_as_issuer(self, tmp_path):
        root = _write_ca(tmp_path)
        fake_ca_cert, fake_ca_key, _ = root.issue_certificate("Fake CA")
        fake = CertificateFactory(
            _Loader(fake_ca_cert, fake_ca_key, root._ca.base_info)
        )
        leaf, _, _ = fake.issue_certificate("victim")
        with pytest.raises(ValidationCertError, match="not a CA"):
            root.validate_chain(leaf, [fake_ca_cert])

    def test_manager_verifies_chain_and_intermediate_revocation(self, tmp_path):
        db = SyncDBHandler(db_url=f"sqlite:///{tmp_path}/ca.db")
        mgr = CertLifecycleManager(
            storage=LocalStorage(tmp_path / "certs"),
            db_handler=db,
            factory=_write_ca(tmp_path),
        )
        inter_cert, inter_key = mgr.issue_intermediate_ca("Inter", key_size=2048)
        inter = CertificateFactory(
            _Loader(inter_cert, inter_key, mgr.factory._ca.base_info)
        )
        leaf, _, _ = inter.issue_certificate("leaf")
        assert mgr.verify_certificate(leaf, intermediates=[inter_cert])

        mgr.revoke_certificate(inter_cert.serial_number, x509.ReasonFlags.ca_compromise)
        with pytest.raises(ValidationCertError, match="revoked"):
            mgr.verify_certificate(leaf, intermediates=[inter_cert])

    def test_tampered_signature(self, tmp_path):
        root = _write_ca(tmp_path)
        impostor = _write_ca(tmp_path / "impostor")
        forged, _, _ = impostor.issue_certificate("svc")  # same issuer name
        with pytest.raises(ValidationCertError, match="Signature"):
            root.validate_cert(forged)


# ---------------------------------------------------------------------------
# Serial numbers
# ---------------------------------------------------------------------------


class TestSerial:
    def test_full_64_random_bits(self):
        top_bits = {
            (SerialWithEncoding.generate("x", CertType.SERVICE) >> 62) & 0b11
            for _ in range(400)
        }
        assert top_bits == {0, 1, 2, 3}

    def test_non_ascii_name_does_not_corrupt_prefix(self):
        serial = SerialWithEncoding.generate("сервер-дрон-1", CertType.DEVICE)
        cert_type, name = SerialWithEncoding.parse(serial)
        assert cert_type is CertType.DEVICE
        assert name == "??????-???"
        assert serial.bit_length() <= 159  # fits 20 DER octets, positive

    def test_encode_rejects_non_ascii(self):
        with pytest.raises(ValueError):
            SerialWithEncoding._encode_name("é")


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


class TestMisc:
    def test_library_logger_is_not_configured(self):
        assert DEFAULT_LOGGER.level == logging.NOTSET
        assert all(isinstance(h, logging.NullHandler) for h in DEFAULT_LOGGER.handlers)

    def test_utc_naive(self):
        aware = datetime.datetime(
            2026, 1, 1, 12, tzinfo=datetime.timezone(datetime.timedelta(hours=2))
        )
        assert utc_naive(aware) == datetime.datetime(2026, 1, 1, 10)
        naive = datetime.datetime(2026, 1, 1)
        assert utc_naive(naive) is naive

    def test_cert_type_from_record_fallback(self):
        assert (
            cert_type_from_record(CertificateRecord(key_type="???")) is CertType.SERVICE
        )
        assert (
            cert_type_from_record(CertificateRecord(key_type="DEV")) is CertType.DEVICE
        )

    def test_get_by_name_tolerates_duplicates(self, env):
        mgr, db, _ = env
        a, _, _ = mgr.issue_certificate(ClientConfig(common_name="dup"))
        b = mgr.factory.issue_certificate("dup")[0]
        assert db.register_cert_in_db(b, uuid="manual", key_type=CertType.SERVICE)
        assert db.get_by_name("dup").serial_number == str(b.serial_number)

    def test_signing_hash(self):
        assert signing_hash(generate_private_key(KeyAlgorithm.ED25519)) is None
        assert signing_hash(generate_private_key(KeyAlgorithm.EC_P384)).name == "sha384"
        assert isinstance(generate_private_key(), ec.EllipticCurvePrivateKey)
        rsa_2048 = generate_private_key(KeyAlgorithm.RSA, 2048)
        assert signing_hash(rsa_2048).name == "sha256"
        assert signing_hash(rsa_2048.public_key()).name == "sha256"
        assert signing_hash(generate_private_key(KeyAlgorithm.RSA)).name == "sha384"
        assert signing_hash(generate_private_key(KeyAlgorithm.EC_P256)).name == "sha256"
        assert (
            certificate_common_name(
                CertificateFactory.build_self_signed_ca(common_name="Z")[0]
            )
            == "Z"
        )

    def test_revoked_rows_have_named_fields(self, env):
        mgr, db, _ = env
        cert, _, _ = mgr.issue_certificate(ClientConfig(common_name="svc"))
        mgr.revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        rows = list(db.get_revoked_certificates())
        assert rows[0].serial_number == str(cert.serial_number)
        assert rows[0].revocation_reason == x509.ReasonFlags.key_compromise.value


# ---------------------------------------------------------------------------
# Edge cases of chain validation and cleanup
# ---------------------------------------------------------------------------


def _raw_ca_child(root: CertificateFactory, cn: str, extensions):
    key = generate_private_key(KeyAlgorithm.EC_P256)
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
        .issuer_name(root._ca.ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=5))
    )
    for ext in extensions:
        builder = builder.add_extension(ext, critical=True)
    cert = builder.sign(root._ca.ca_key, signing_hash(root._ca.ca_key))
    from tiny_ca.models.certificate import CertificateInfo

    info = CertificateInfo(organization=None, country=None)
    return cert, CertificateFactory(_Loader(cert, key, info))


class TestChainEdgeCases:
    def test_issuer_without_basic_constraints(self, tmp_path):
        root = _write_ca(tmp_path)
        cert, child = _raw_ca_child(root, "NoBC", [])
        leaf, _, _ = child.issue_certificate("leaf")
        with pytest.raises(ValidationCertError, match="not a CA"):
            root.validate_chain(leaf, [cert])

    def test_issuer_without_key_cert_sign(self, tmp_path):
        root = _write_ca(tmp_path)
        ku = x509.KeyUsage(
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
        cert, child = _raw_ca_child(
            root, "NoKU", [x509.BasicConstraints(ca=True, path_length=None), ku]
        )
        leaf, _, _ = child.issue_certificate("leaf")
        with pytest.raises(ValidationCertError, match="keyCertSign"):
            root.validate_chain(leaf, [cert])

    def test_issuer_without_key_usage_is_accepted(self, tmp_path):
        root = _write_ca(tmp_path)
        cert, child = _raw_ca_child(
            root, "BCOnly", [x509.BasicConstraints(ca=True, path_length=None)]
        )
        leaf, _, _ = child.issue_certificate("leaf")
        assert len(root.validate_chain(leaf, [cert])) == 3

    def test_intermediate_without_org_or_country(self, tmp_path):
        root = _write_ca(tmp_path)
        _, child = _raw_ca_child(
            root, "Bare", [x509.BasicConstraints(ca=True, path_length=None)]
        )
        sub, _ = child.issue_intermediate_ca("Sub", key_algorithm=KeyAlgorithm.ED25519)
        assert [a.oid for a in sub.subject] == [x509.NameOID.COMMON_NAME]

    def test_chain_too_long(self, tmp_path):
        root = _write_ca(tmp_path)
        issuer = root
        chain = []
        for i in range(11):
            cert, key = issuer.issue_intermediate_ca(
                f"I{i}", path_length=None, key_algorithm=KeyAlgorithm.EC_P256
            )
            chain.append(cert)
            issuer = CertificateFactory(_Loader(cert, key, root._ca.base_info))
        leaf, _, _ = issuer.issue_certificate("leaf")
        with pytest.raises(ValidationCertError, match="too long"):
            root.validate_chain(leaf, chain)

    def test_cosign_ca_certificate_uses_ca_serial_type(self, tmp_path):
        ours = _write_ca(tmp_path / "ours")
        foreign_root, _ = CertificateFactory.build_self_signed_ca(common_name="F")
        cosigned = ours.cosign_certificate(foreign_root)
        assert SerialWithEncoding.parse(cosigned.serial_number)[0] is CertType.CA


class _MemoryStorage(LocalStorage.__mro__[1]):  # BaseStorage
    """Non-filesystem storage used to check cleanup with foreign backends."""

    def __init__(self):
        self.saved: list[str] = []

    def save_certificate(self, cert, file_name, cert_path=None, uuid_str=None, **_):
        self.saved.append(file_name)
        return Path(f"/nonexistent/{uuid_str}/{file_name}"), uuid_str or "mem"

    def delete_certificate_folder(self, uuid_str, cert_path=None):
        return True


class TestCleanupEdgeCases:
    def test_failure_before_any_write(self, env):
        mgr, _, _ = env
        with pytest.raises(InvalidPathError):
            mgr.issue_certificate(ClientConfig(common_name="svc"), cert_path="/etc")

    def test_foreign_storage_files_are_left_alone(self, tmp_path):
        db = SyncDBHandler(db_url=f"sqlite:///{tmp_path}/ca.db")
        storage = _MemoryStorage()
        mgr = CertLifecycleManager(
            storage=storage, db_handler=db, factory=_write_ca(tmp_path)
        )
        with (
            patch.object(db, "register_cert_in_db", return_value=False),
            pytest.raises(DBOperationError),
        ):
            mgr.issue_certificate(ClientConfig(common_name="svc"), uuid_str="u")
        assert storage.saved == ["svc", "svc", "svc"]


def test_cosign_with_explicit_serial_type(tmp_path):
    ours = _write_ca(tmp_path)
    foreign_root, _ = CertificateFactory.build_self_signed_ca(common_name="X")
    cosigned = ours.cosign_certificate(foreign_root, serial_type=CertType.USER)
    assert SerialWithEncoding.parse(cosigned.serial_number)[0] is CertType.USER
