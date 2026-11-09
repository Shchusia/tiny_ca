#!/usr/bin/env python3
"""
High-assurance features of tiny-ca 1.0.

1. A root CA whose private key is only reachable through a signer (an HSM
   stand-in here; use ``Pkcs11Signer`` / ``SignerCALoader.from_pkcs11`` with
   a real token).
2. Certificate policies on everything the CA signs.
3. A name-constrained subordinate CA certified from a CSR (its key lives in
   "another HSM"), and the constraint being enforced.
4. A signed, hash-chained audit log, verified at the end.

Run with: python examples/high_assurance_example.py
"""

from __future__ import annotations

from pathlib import Path
import tempfile

from cryptography import x509
from cryptography.x509.oid import NameOID

from tiny_ca import (
    AuditLog,
    CertificateFactory,
    CertLifecycleManager,
    ClientConfig,
    KeyAlgorithm,
    NameConstraintsConfig,
    SignerCALoader,
    SyncDBHandler,
)
from tiny_ca.exc import NameConstraintViolation
from tiny_ca.signing import sign_bytes
from tiny_ca.storage import LocalStorage
from tiny_ca.utils.keys import generate_private_key, signing_hash

POLICY_OID = "1.3.6.1.4.1.55555.1.1"  # replace with your certificate policy


class DemoToken:
    """
    Stand-in for an HSM key: it exposes only ``public_key()`` and ``sign()``.
    With a real token use ``tiny_ca.Pkcs11Signer.open(...)`` instead.
    """

    def __init__(self) -> None:
        self._key = generate_private_key(KeyAlgorithm.EC_P384)

    def public_key(self):
        return self._key.public_key()

    def sign(self, data, algorithm):
        return sign_bytes(self._key, data, algorithm)

    def csr(self) -> x509.CertificateSigningRequest:
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sub")]))
            .sign(self._key, signing_hash(self._key))
        )


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="tiny_ca_ha_"))
    print(f"Working directory: {work}")

    # 1. Root CA whose key never leaves the "token".
    root_token = DemoToken()
    root_cert = CertificateFactory.build_self_signed_ca_with_signer(
        root_token, common_name="ACME Root CA", organization="ACME", country="UA"
    )
    print(f"Root CA: {root_cert.subject.rfc4514_string()}")

    # 4. Audit log signed with a dedicated key.
    audit_key = generate_private_key()
    audit = AuditLog(work / "audit.jsonl", signer=audit_key, actor="ceremony-1")

    # 2. Factory with certificate policies, operated through the signer.
    root = CertLifecycleManager(
        storage=LocalStorage(work / "root"),
        db_handler=SyncDBHandler(db_url=f"sqlite:///{work}/root.db"),
        factory=CertificateFactory(
            SignerCALoader(root_cert, root_token),
            certificate_policies=[POLICY_OID],
            cps_uri="https://pki.example.com/cps",
            crl_distribution_points=["http://pki.example.com/root.crl"],
        ),
        audit_log=audit,
    )

    # 3. Subordinate CA: key in another token, certified from its CSR and
    #    limited to example.com / 10.0.0.0/8.
    sub_token = DemoToken()
    sub_cert = root.certify_intermediate_ca(
        sub_token.csr(),
        common_name="ACME Issuing CA",
        name_constraints=NameConstraintsConfig(
            permitted_dns=["example.com"], permitted_ip=["10.0.0.0/8"]
        ),
    )
    print(f"Subordinate CA: {sub_cert.subject.rfc4514_string()}")

    issuing = CertLifecycleManager(
        storage=LocalStorage(work / "issuing"),
        db_handler=SyncDBHandler(db_url=f"sqlite:///{work}/issuing.db"),
        factory=CertificateFactory(
            SignerCALoader(sub_cert, sub_token), certificate_policies=[POLICY_OID]
        ),
        audit_log=audit,
    )
    leaf, _, _ = issuing.issue_certificate(
        ClientConfig(common_name="api.example.com", san_ip=["10.1.2.3"])
    )
    policies = leaf.extensions.get_extension_for_class(x509.CertificatePolicies)
    print(
        f"Leaf issued: {leaf.subject.rfc4514_string()}, "
        f"policy {policies.value[0].policy_identifier.dotted_string}"
    )

    path = root.factory.validate_chain(leaf, [sub_cert])  # type: ignore[union-attr]
    print(f"Chain valid: {' -> '.join(c.subject.rfc4514_string() for c in path)}")

    try:
        issuing.issue_certificate(ClientConfig(common_name="www.other.org"))
    except NameConstraintViolation as exc:
        print(f"Refused as expected: {exc.message}")

    root.generate_crl()

    count = AuditLog.verify(
        audit.path, public_key=audit_key.public_key(), expected_head=audit.head
    )
    print(f"Audit log verified: {count} signed entries")
    for entry in AuditLog.entries(audit.path):
        print(f"  #{entry['seq']} {entry['event']} {entry['data'].get('subject', '')}")


if __name__ == "__main__":
    main()
