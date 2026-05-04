Quick Start
===========

1. Bootstrap a Root CA
----------------------

.. code-block:: python

    from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
    from tiny_ca.storage.local_storage import LocalStorage
    from tiny_ca.db.sync_db_manager import SyncDBHandler
    from tiny_ca.models.certificate import CAConfig

    storage = LocalStorage(base_folder="./pki")
    db = SyncDBHandler(db_url="sqlite:///pki.db")
    mgr = CertLifecycleManager(storage=storage, db_handler=db)

    cert_path, key_path = mgr.create_self_signed_ca(
        CAConfig(
            common_name="My Root CA",
            organization="ACME Corp",
            country="UA",
            key_size=4096,
            days_valid=3650,
        )
    )

.. note::

    This step creates a **self-signed Root CA**.
    Store the private key securely — compromise of this key breaks trust for all issued certificates.

Attach the factory:

.. code-block:: python

    from tiny_ca.ca_factory.utils.file_loader import CAFileLoader
    from tiny_ca.ca_factory.factory import CertificateFactory

    loader = CAFileLoader(ca_cert_path=cert_path, ca_key_path=key_path)
    mgr.factory = CertificateFactory(loader)

.. warning::

    Without attaching a ``CertificateFactory``, the manager **cannot issue certificates**.


2. Issue a Leaf Certificate
---------------------------

.. code-block:: python

    from tiny_ca.models.certificate import ClientConfig
    from tiny_ca.const import CertType

    cert, key, csr = mgr.issue_certificate(
        ClientConfig(
            common_name="nginx.internal",
            serial_type=CertType.SERVICE,
            key_size=2048,
            days_valid=365,
            is_server_cert=True,
            san_dns=["nginx.internal", "www.nginx.internal"],
            san_ip=["192.168.1.10"],
        ),
        cert_path="services",
    )

.. note::

    Subject Alternative Names (SAN) are required by modern TLS clients.
    The Common Name (CN) alone is **not sufficient** for hostname validation.


3. Renew a Certificate (same key)
---------------------------------

.. code-block:: python

    renewed_cert = mgr.renew_certificate(
        serial=cert.serial_number,
        days_valid=365
    )

.. note::

    Renewal keeps the **same key pair**.
    Use this only if the private key is still secure.


4. Rotate a Certificate (new key)
---------------------------------

.. code-block:: python

    new_cert, new_key, new_csr = mgr.rotate_certificate(
        serial=cert.serial_number,
        config=ClientConfig(
            common_name="nginx.internal",
            serial_type=CertType.SERVICE,
            days_valid=365,
            is_server_cert=True,
        ),
    )

.. warning::

    Rotation **revokes the old certificate** automatically.
    Ensure all clients switch to the new certificate before enforcing revocation.


5. Revoke a Certificate
-----------------------

.. code-block:: python

    from cryptography import x509

    ok = mgr.revoke_certificate(
        serial=cert.serial_number,
        reason=x509.ReasonFlags.key_compromise,
    )

.. warning::

    Revocation is irreversible.
    Once revoked, a certificate should never be trusted again.


6. Generate and Verify a CRL
----------------------------

.. code-block:: python

    crl = mgr.generate_crl(days_valid=7)
    mgr.verify_crl(crl)

.. note::

    CRLs must be **periodically regenerated and distributed** to relying parties.


7. Export PKCS#12
-----------------

.. code-block:: python

    p12_bytes = mgr.export_pkcs12(
        cert=cert,
        private_key=key,
        password=b"strong-passphrase",
        name="nginx.internal",
    )

.. warning::

    Always protect PKCS#12 bundles with a strong password.
    They contain the **private key in exportable form**.


8. Inspect a Certificate
------------------------

.. code-block:: python

    details = mgr.inspect_certificate(cert)

    print(details.common_name)
    print(details.san_dns)
    print(details.san_ip)
    print(details.fingerprint_sha256)
    print(details.public_key_size)
    print(details.is_ca)

.. note::

    This method returns a **safe, serialisable snapshot** — no raw cryptography objects.


9. List and Monitor Certificates
--------------------------------

.. code-block:: python

    records = mgr.list_certificates(
        status="valid",
        key_type="service",
        limit=50,
        offset=0,
    )

    expiring = mgr.get_expiring_soon(within_days=30)
    for r in expiring:
        print(r.common_name, r.not_valid_after)

    updated = mgr.refresh_expired_statuses()
    deleted = mgr.delete_certificate(serial=cert.serial_number)

.. note::

    Regular monitoring helps prevent **unexpected certificate expiration outages**.

.. warning::

    Hard deletion removes both the database record and stored files.
    This action cannot be undone.
