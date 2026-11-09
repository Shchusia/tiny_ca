High-Assurance Deployments
==========================

tiny-ca 1.0 provides the building blocks of a high-assurance PKI:

* the CA key held in an HSM;
* strong defaults;
* certificate policies and name constraints;
* fail-closed revocation checks;
* a signed audit trail.

The library itself is **not** certified against any national, NATO or Common
Criteria scheme.  Its cryptography (``cryptography`` / OpenSSL) is not a
FIPS 140-3 validated module unless you build it against one.  Operating
environment, role separation, key ceremonies and the CP/CPS have to be
covered separately.

Keep the CA key in an HSM
-------------------------

Install the extra with ``pip install 'tiny-ca[hsm]'``, then:

.. code-block:: python

    import os
    from tiny_ca import CertificateFactory, SignerCALoader

    loader = SignerCALoader.from_pkcs11(
        ca_cert="pki/ca.pem",                       # the certificate only
        module_path="/usr/lib/softhsm/libsofthsm2.so",
        token_label="ca-token",
        pin=os.environ["CA_TOKEN_PIN"],
        key_label="root-ca",
    )
    mgr.factory = CertificateFactory(loader)
    ...
    loader.ca_signer.close()

At start-up the loader checks that:

* the certificate is a CA;
* the token key matches the certificate;
* the token can sign a random challenge.

Every signature the token returns is verified against the CA certificate.
Other back-ends (cloud KMS, remote signing services) implement
:class:`tiny_ca.signing.CASigner`.

For key pairs generated on a token, certify them without the key ever
leaving the token:

* :meth:`tiny_ca.ca_factory.factory.CertificateFactory.build_self_signed_ca_with_signer`
  for a root;
* :meth:`~tiny_ca.managers.sync_lifecycle_manager.CertLifecycleManager.certify_intermediate_ca`
  (CSR or public key) for a subordinate CA.

Certificate policies and name constraints
-----------------------------------------

.. code-block:: python

    from tiny_ca import CertificateFactory, NameConstraintsConfig

    mgr.factory = CertificateFactory(
        loader,
        certificate_policies=["1.3.6.1.4.1.55555.1.1"],
        cps_uri="https://pki.example.com/cps",
    )
    sub_cert, sub_key = mgr.issue_intermediate_ca(
        "Issuing CA - example.com",
        name_constraints=NameConstraintsConfig(
            permitted_dns=["example.com"], permitted_ip=["10.0.0.0/8"]
        ),
    )

``NameConstraints`` (DNS / IP / e-mail) is enforced by ``validate_chain`` and
at issuance, renewal and co-signing.  Wildcards are checked against excluded
subtrees.  Unsupported name types fail closed.

Tamper-evident audit log
------------------------

.. code-block:: python

    from tiny_ca import AuditLog, CertLifecycleManager

    audit = AuditLog("/var/log/pki/audit.jsonl", signer=audit_key,
                     actor="pki-operator-1")
    mgr = CertLifecycleManager(storage=storage, db_handler=db,
                               factory=factory, audit_log=audit)

    AuditLog.verify("/var/log/pki/audit.jsonl",
                    public_key=audit_key.public_key(),
                    expected_head=last_published_head)

Every state-changing operation appends a hash-chained, optionally signed JSON
line.  To detect truncation of the tail, publish ``audit.head`` to a place the
CA host cannot rewrite.

Defaults
--------

* Keys: ECDSA P-384.  RSA defaults to 3072 bits; 2048–8192 bits are
  accepted.
* Signature digest: SHA-384 for P-384 and RSA ≥ 3072.
* Leaf validity: 365 days (1–36500 accepted).  Issued certificates never
  outlive their CA.

A runnable walk-through is in ``examples/high_assurance_example.py``.
