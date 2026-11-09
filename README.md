# tiny_ca

[![Python](https://img.shields.io/pypi/pyversions/tiny-ca)](https://pypi.org/project/tiny-ca/)
[![PyPI](https://img.shields.io/pypi/v/tiny-ca?color=blue)](https://pypi.org/project/tiny-ca/)
[![Downloads](https://static.pepy.tech/badge/tiny-ca)](https://pepy.tech/projects/tiny-ca)
[![Downloads/month](https://static.pepy.tech/badge/tiny-ca/month)](https://pepy.tech/projects/tiny-ca)

[![Coverage Status](https://coveralls.io/repos/github/Shchusia/tiny_ca/badge.svg?branch=feature/docs)](https://coveralls.io/github/Shchusia/tiny_ca?branch=feature/docs)
[![Docs](https://img.shields.io/badge/Docs-passing-green)](https://shchusia.github.io/tiny_ca/)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

A lightweight, **100%-tested** Python library for managing the full lifecycle of X.509 certificates — from bootstrapping a self-signed root CA to issuing, revoking, rotating, renewing, and co-signing end-entity certificates, generating and verifying CRLs, exporting PKCS#12 bundles, and issuing intermediate CAs — all backed by pluggable sync/async storage and database adapters.

---

## REST API

> Looking for a ready-to-use HTTP server built on **tiny-ca**?
> Check out **[tiny-ca-gateway](https://github.com/Shchusia/tiny-ca-gateway)** — a framework-agnostic REST API adapter that exposes all 22 certificate lifecycle endpoints with no extra code.

| | |
|---|---|
| **GitHub** | [github.com/Shchusia/tiny-ca-gateway](https://github.com/Shchusia/tiny-ca-gateway) |
| **Integration guide** | [tiny-ca-gateway/blob/master/README.md](https://github.com/Shchusia/tiny-ca-gateway/blob/master/README.md) |
| **Supported frameworks** | FastAPI · Flask · aiohttp · Django Ninja |

```bash
pip install "tiny-ca-gateway[fastapi]"   # FastAPI + Uvicorn
pip install "tiny-ca-gateway[flask]"     # Flask + Gunicorn
pip install "tiny-ca-gateway[aiohttp]"   # aiohttp
pip install "tiny-ca-gateway[django]"    # Django + Django Ninja
```

```python
# FastAPI — all 22 CA endpoints in 5 lines
from fastapi import FastAPI
from contextlib import asynccontextmanager
from tiny_ca_gateway.fastapi.lifespan.manager import FastAPILifespanManager
from tiny_ca_gateway.fastapi.api.v1.ca_routes import router

@asynccontextmanager
async def lifespan(app: FastAPI):
    await FastAPILifespanManager(common_name="My CA").on_startup()
    yield

app = FastAPI(lifespan=lifespan)
app.include_router(router, prefix="/api/v1")
# → Swagger UI at http://localhost:8000/docs
```

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [High-Assurance Deployments](#high-assurance-deployments)
- [Complete Examples](#complete-examples)
- [Configuration Models](#configuration-models)
- [Storage Backends](#storage-backends)
- [Database Adapters](#database-adapters)
- [Serial Number Encoding](#serial-number-encoding)
- [Error Reference](#error-reference)
- [FAQ](#faq)
- [Migrating from Other CAs](#migrating-from-other-cas)
- [Benchmark Results](#benchmark-results)
- [Project Structure](#project-structure)
- [Security Model](#security-model)
- [Security Policy](#security-policy)
- [License](#license)

---

## Features

| Category | Capability |
|---|---|
| **CA bootstrap** | Self-signed root CA and intermediate (sub) CA with configurable `path_length` |
| **Issuance** | Leaf certificates with SANs (DNS + IP), EKU (Server/Client Auth), email attribute |
| **Key algorithms** | ECDSA P-384 (default), P-256, RSA 2048–8192 (default 3072), Ed25519; SHA-384 signatures for P-384 / RSA ≥ 3072 |
| **HSM / external signers** | CA key in an HSM or smart card via PKCS#11 (`SignerCALoader`, `Pkcs11Signer`) or any `CASigner` (cloud KMS); root and subordinate CA certificates for keys that never leave the token |
| **Policies & name constraints** | `CertificatePolicies` with CPS pointer on every certificate; critical `NameConstraints` (DNS / IP / e-mail) on intermediates, enforced at issuance and in chain validation |
| **Audit log** | Hash-chained, signed, append-only JSONL log of every CA operation with offline verification |
| **Lifecycle** | Revoke (RFC 5280 reasons), renew (same key), rotate (new key), hard-delete — every CA-signed certificate is registered, so it can always be revoked |
| **CRL** | RFC 5280 CRLs with `CRLNumber`, AKI and per-entry reason codes; optional CRL Distribution Points / AIA in issued certificates |
| **Validation** | Direct (`validate_cert`) or through intermediates (`validate_chain`, with `BasicConstraints` / `pathLen` checks); registry check is fail-closed |
| **Inspection** | Structured `CertificateDetails` snapshot from any `x509.Certificate` — fully serialisable |
| **Export** | PKCS#12 (`.p12`/`.pfx`) bundles with full CA chain |
| **Co-signing** | Re-sign third-party certificates under your CA, preserving Subject and extensions |
| **Chain** | Build `[leaf, ca]` fullchain ready for nginx, Apache, or Envoy |
| **Monitoring** | List certs with filters, find expiring-soon, bulk-expire stale records |
| **Storage** | `LocalStorage` (sync) and `AsyncLocalStorage` (async) with UUID-based isolation, `0600` private keys and path-traversal protection |
| **Database** | `SyncDBHandler` (SQLAlchemy) and `AsyncDBHandler` (aiosqlite) — SQLite, PostgreSQL, MySQL |
| **API parity** | `CertLifecycleManager` and `AsyncCertLifecycleManager` are feature-identical |
| **Serial numbers** | `SerialWithEncoding` — 160-bit RFC 5280-compliant, type-prefixed, name-encoded |
| **Test coverage** | **100 %** line and branch coverage across all modules |

---

## Requirements

- **Python** 3.11 or higher
- **Core:** `cryptography >= 46`, `sqlalchemy >= 2`, `pydantic >= 2`
- **Async extras:** `aiosqlite`
- **PostgreSQL:** `psycopg2-binary` (sync) / `asyncpg` (async)
- **MySQL:** `pymysql` (sync) / `aiomysql` (async)
- **HSM:** `python-pkcs11` (`tiny-ca[hsm]`)

---

## Architecture

```
CertLifecycleManager / AsyncCertLifecycleManager   ← application entry-point
        │
        ├── CertificateFactory                      ← crypto-only, zero I/O
        │       ├── ICALoader (Protocol)
        │       │       ├── CAFileLoader            ← sync PEM file loader
        │       │       └── AsyncCAFileLoader       ← async PEM file loader
        │       ├── ISignerCALoader (Protocol)
        │       │       └── SignerCALoader          ← CA cert + CASigner (HSM / KMS)
        │       ├── CASigner (Protocol)             ← KeySigner, Pkcs11Signer
        │       ├── CertLifetime                    ← validity window helpers
        │       ├── CertSerialParser                ← read serials from certs
        │       └── SerialWithEncoding              ← encode / decode serial numbers
        │
        ├── BaseStorage (ABC)
        │       ├── LocalStorage                    ← sync filesystem (UUID-isolated)
        │       └── AsyncLocalStorage               ← async filesystem (worker threads)
        │
        ├── BaseDB (ABC)
        │       ├── SyncDBHandler                   ← SQLAlchemy sync
        │       └── AsyncDBHandler                  ← SQLAlchemy async (aiosqlite)
        │
        └── AuditLog                                ← optional signed, hash-chained log
```

Every component is injected at construction time — no global singletons, trivially testable.

---

## Installation

```bash
# Core sync-only
pip install tiny-ca

# With async support (recommended)
pip install tiny-ca[async]

# PostgreSQL
pip install tiny-ca[postgres]           # sync (psycopg2)
pip install tiny-ca[postgres-async]     # async (asyncpg)

# MySQL
pip install tiny-ca[mysql]              # sync (pymysql)
pip install tiny-ca[mysql-async]        # async (aiomysql)

# HSM / smart card (PKCS#11)
pip install tiny-ca[hsm]

# Everything
pip install tiny-ca[all]
```

---

## Quick Start

### 1. Bootstrap a Root CA

```python
from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
from tiny_ca.storage.local_storage import LocalStorage
from tiny_ca.db.sync_db_manager import SyncDBHandler
from tiny_ca.models.certificate import CAConfig

from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

# Private keys are always written with mode 0600; encrypt them at rest too.
storage = LocalStorage(
    base_folder="./pki",
    base_encryption_algorithm=BestAvailableEncryption(b"key-passphrase"),
)
db = SyncDBHandler(db_url="sqlite:///pki.db")
mgr = CertLifecycleManager(storage=storage, db_handler=db)

cert_path, key_path = mgr.create_self_signed_ca(
    CAConfig(common_name="My Root CA", organization="ACME Corp",
             country="UA", days_valid=3650)          # ECDSA P-384 by default
)
```

Attach the factory so the manager can issue certificates:

```python
from tiny_ca.ca_factory.utils.file_loader import CAFileLoader
from tiny_ca.ca_factory.factory import CertificateFactory

loader = CAFileLoader(ca_cert_path=cert_path, ca_key_path=key_path,
                      ca_key_password=b"key-passphrase")
mgr.factory = CertificateFactory(
    loader,
    # Optional: tell relying parties where to find the CRL / CA certificate.
    crl_distribution_points=["http://pki.example/crl.pem"],
    ca_issuers_urls=["http://pki.example/ca.pem"],
)
```

Keys default to ECDSA P-384 (signatures with SHA-384).  `CAConfig` /
`ClientConfig` accept `key_algorithm=KeyAlgorithm.RSA` (3072-bit by default),
`EC_P256` or `ED25519` — see [Configuration Models](#configuration-models).
To keep the CA key in an HSM, see
[High-Assurance Deployments](#high-assurance-deployments).

### 2. Issue a Leaf Certificate

```python
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
```

### 3. Renew a Certificate (same key)

Keeps the existing public key — only validity window and serial number change.
Use when the key has **not** been compromised.  The renewed certificate is
stored and registered (so it can be revoked); the original is revoked with
reason `superseded`.  The private key stays in the original folder.

```python
renewed = mgr.renew_certificate(serial=cert.serial_number, days_valid=365)
```

### 4. Rotate a Certificate (new key)

Issues a replacement with a fresh key pair, then revokes the old cert
(`superseded`).  If the old cert cannot be revoked, the replacement is rolled
back and `CertRevocationError` is raised.

```python
new_cert, new_key, new_csr = mgr.rotate_certificate(
    serial=cert.serial_number,
    config=ClientConfig(common_name="nginx.internal",
                        serial_type=CertType.SERVICE, days_valid=365,
                        is_server_cert=True),
)
```

### 5. Revoke a Certificate

```python
from cryptography import x509
mgr.revoke_certificate(serial=cert.serial_number, reason=x509.ReasonFlags.key_compromise)
```

### 6. Generate and Verify a CRL

```python
crl = mgr.generate_crl(days_valid=7)   # written to <base_folder>/crl.pem
mgr.verify_crl(crl)                     # raises ValidationCertError on failure
```

Revoked certificates stay on the CRL until they expire.  If the database
cannot be read, `generate_crl` raises `DBOperationError` and the previous
`crl.pem` is left untouched — an empty CRL is never published.

### 7. Issue an Intermediate CA

```python
sub_ca_cert, sub_ca_key = mgr.issue_intermediate_ca(
    common_name="Issuing CA", key_size=4096, days_valid=1825,
    path_length=0, organization="ACME Corp", country="UA",
    cert_path="intermediate",
)

# The intermediate is registered (revocable via the root's CRL).  Verify a
# leaf issued by it through the chain:
mgr.verify_certificate(leaf_cert, intermediates=[sub_ca_cert])
```

Pass `name_constraints=NameConstraintsConfig(...)` to restrict the names the
intermediate may certify.  Use `certify_intermediate_ca(csr, ...)` when its
key is generated elsewhere (e.g. in its own HSM).

### 8. Export PKCS#12

```python
p12_bytes = mgr.export_pkcs12(cert=cert, private_key=key,
                               password=b"strong-passphrase", name="nginx.internal")
with open("nginx.p12", "wb") as f:
    f.write(p12_bytes)
```

### 9. Co-sign a Third-Party Certificate

```python
from cryptography import x509
third_party = x509.load_pem_x509_certificate(open("partner.pem", "rb").read())
cosigned = mgr.cosign_certificate(cert=third_party, days_valid=365)
# stored + registered like any other certificate issued by this CA
```

### 10. Inspect a Certificate

```python
details = mgr.inspect_certificate(cert)
print(details.common_name, details.fingerprint_sha256, details.public_key_size)

# Build fullchain.pem for nginx
from cryptography.hazmat.primitives.serialization import Encoding
chain = mgr.get_cert_chain(cert)
fullchain_pem = b"".join(c.public_bytes(Encoding.PEM) for c in chain)
```

### 11. Monitor Certificates

```python
records  = mgr.list_certificates(status="valid", key_type="service", limit=50)
expiring = mgr.get_expiring_soon(within_days=30)
updated  = mgr.refresh_expired_statuses()   # run periodically
mgr.delete_certificate(serial=cert.serial_number)  # revoked + unexpired → CertificateRevokedError (keeps the CRL entry)
```

### 12. Async Usage

```python
import asyncio
from tiny_ca.managers.async_lifecycle_manager import AsyncCertLifecycleManager
from tiny_ca.storage.async_local_storage import AsyncLocalStorage
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.models.certificate import CAConfig, ClientConfig
from tiny_ca.const import CertType

async def main():
    storage = AsyncLocalStorage(base_folder="./pki_async")
    db = AsyncDBHandler(db_url="sqlite+aiosqlite:///pki_async.db")
    await db._db.init_db()

    mgr = AsyncCertLifecycleManager(storage=storage, db_handler=db)
    cert_path, key_path = await mgr.create_self_signed_ca(
        CAConfig(common_name="Async CA", organization="ACME",
                 country="UA", key_size=2048, days_valid=3650)
    )

    from tiny_ca.ca_factory.utils.afile_loader import AsyncCAFileLoader
    from tiny_ca.ca_factory.factory import CertificateFactory
    loader = await AsyncCAFileLoader.create(cert_path, key_path)
    mgr.factory = CertificateFactory(loader)

    cert, key, csr = await mgr.issue_certificate(
        ClientConfig(common_name="api.internal", serial_type=CertType.SERVICE,
                     days_valid=365, is_server_cert=True)
    )
    details = await mgr.inspect_certificate(cert)
    p12 = await mgr.export_pkcs12(cert, key, password=b"secret")

asyncio.run(main())
```

## High-Assurance Deployments

Features for PKIs that run under a formal security policy.  See
[Security Model](#security-model) for what they do and do not guarantee.

### Keep the CA key in an HSM

The CA key can live in an HSM or smart card and never be loaded into the
process.  Install the extra: `pip install 'tiny-ca[hsm]'`.

```python
import os
from tiny_ca import CertificateFactory, SignerCALoader

loader = SignerCALoader.from_pkcs11(
    ca_cert="pki/ca.pem",                         # the certificate only, no key file
    module_path="/usr/lib/softhsm/libsofthsm2.so",
    token_label="ca-token",
    pin=os.environ["CA_TOKEN_PIN"],
    key_label="root-ca",                          # or key_id=b"\x01"
)
mgr.factory = CertificateFactory(loader)
# ... issue, renew, revoke, build CRLs: every signature is made by the token
loader.ca_signer.close()                          # end the PKCS#11 session
```

At start-up `SignerCALoader` checks three things:
- the certificate is a CA;
- the token key matches the certificate;
- the token can sign a random challenge.

Every signature the token returns is verified against the CA certificate
before a certificate or CRL leaves the factory.  Any other back-end (cloud
KMS, remote signing service) plugs in through the `CASigner` protocol:

```python
from tiny_ca import CASigner, SignerCALoader

class KmsSigner:                                   # satisfies CASigner
    def public_key(self):
        return ca_cert.public_key()

    def sign(self, data: bytes, algorithm) -> bytes:
        # algorithm: hashes.SHA384() / SHA256(), or None for Ed25519.
        # Return PKCS#1 v1.5 (RSA), DER ECDSA-Sig-Value (EC) or raw Ed25519.
        return kms_client.sign(data, algorithm)

loader = SignerCALoader(ca_cert, KmsSigner())
```

**Keys generated on the token.**  Create the key pair with the token's
tooling, for example
`pkcs11-tool --keypairgen --key-type EC:secp384r1 --label root-ca`.  Then
certify it without the key ever leaving the token:

```python
from tiny_ca import Pkcs11Signer

# Root CA: the public key comes from the token (or from a CSR made by it).
signer = Pkcs11Signer.open(module_path, "ca-token", pin,
                           public_key=token_public_key, key_label="root-ca")
root_cert = CertificateFactory.build_self_signed_ca_with_signer(
    signer, common_name="ACME Root CA", organization="ACME", country="UA")

# Subordinate CA whose key lives in another HSM: certify its CSR.
sub_cert = mgr.certify_intermediate_ca(sub_ca_csr, common_name="ACME Issuing CA")
```

`certify_intermediate_ca` checks the CSR signature as proof of possession.
It takes the Subject from its own arguments, never from the CSR.  It stores
and registers only the certificate.

### Certificate policies and name constraints

```python
from tiny_ca import CertificateFactory, NameConstraintsConfig

mgr.factory = CertificateFactory(
    loader,
    certificate_policies=["1.3.6.1.4.1.55555.1.1"],   # your CP OID(s)
    cps_uri="https://pki.example.com/cps",
)

sub_cert, sub_key = mgr.issue_intermediate_ca(
    "Issuing CA - example.com",
    name_constraints=NameConstraintsConfig(
        permitted_dns=["example.com"],        # example.com and sub-domains
        excluded_dns=["secret.example.com"],
        permitted_ip=["10.0.0.0/8"],
        permitted_email=["example.com"],       # mailboxes @example.com
    ),
)
```

- `CertificatePolicies` (with an optional CPS pointer) is added to every
  certificate the factory issues, renews, co-signs or certifies.
- `NameConstraints` is a critical extension of the intermediate.  It is
  enforced in two places:
  - `validate_chain` / `verify_certificate` check every certificate below the
    constrained CA;
  - a factory running *on* the constrained CA refuses to issue, renew or
    co-sign a certificate with a forbidden DNS / IP / e-mail name, and
    raises `NameConstraintViolation`.
- Wildcards are handled conservatively: `*.com` is refused when `evil.com`
  is excluded.
- Constraints on name types tiny-ca cannot evaluate (directoryName, URI,
  otherName, registeredID) fail closed.

### Tamper-evident audit log

```python
from tiny_ca import AuditLog, CertLifecycleManager

audit = AuditLog("/var/log/pki/audit.jsonl",
                 signer=audit_key,            # dedicated key or a CASigner (HSM)
                 actor="pki-operator-1")
mgr = CertLifecycleManager(storage=storage, db_handler=db, factory=factory,
                           audit_log=audit)

# ... later, e.g. from a daily job, with the head hash kept elsewhere:
count = AuditLog.verify("/var/log/pki/audit.jsonl",
                        public_key=audit_key.public_key(),
                        expected_head=last_published_head)
```

Every state-changing operation appends one JSON line.  The operations are
CA creation, issuance, rotation, renewal, co-signing, intermediate
issuance or certification, revocation (including failed attempts),
deletion, CRL generation and PKCS#12 export.  Each line holds:
- the sequence number, UTC time, actor and event;
- the certificate serial, subject, issuer and SHA-256 fingerprint;
- the hash of the previous line and the line's own hash;
- a signature, when a signing key is configured.

`AuditLog.verify` detects edited, inserted, reordered and deleted entries.
To detect deletion of the *last* entries, publish `audit.head` regularly to
a place the CA host cannot rewrite (SIEM, ticket, second host) and pass it
as `expected_head`.

### Defaults

| Setting | 1.0 default | Override |
|---|---|---|
| Key algorithm | ECDSA P-384 | `key_algorithm=KeyAlgorithm.RSA / EC_P256 / ED25519` |
| RSA key size | 3072 bits (2048–8192 allowed, warning below 3072) | `key_size=` |
| Signature digest | SHA-384 for P-384 and RSA ≥ 3072, SHA-256 for P-256 / RSA-2048 | follows the CA key |
| Leaf validity | 365 days (1–36500 allowed) | `days_valid=` |
| CA validity | 3650 days; issued certificates never outlive the CA | `days_valid=` |

---

## Complete Examples

| File | Description |
|---|---|
| `examples/complete_example.py` | Sync API — full lifecycle |
| `examples/acomplete_example.py` | Async API — full lifecycle |
| `examples/high_assurance_example.py` | HSM-style signer, certificate policies, name-constrained sub-CA, signed audit log |

```bash
python examples/complete_example.py
python examples/acomplete_example.py
python examples/high_assurance_example.py
```

---

## Configuration Models

### `CAConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `common_name` | `str` | `"Internal CA"` | CA Common Name (CN) |
| `organization` | `str` | `"My Company"` | Organization (O) |
| `country` | `str` | `"UA"` | Two-letter ISO 3166-1 alpha-2 code |
| `key_size` | `int` | `3072` | RSA key length in bits (2048–8192; ignored for EC / Ed25519) |
| `key_algorithm` | `KeyAlgorithm` | `EC_P384` | `EC_P384`, `EC_P256`, `RSA` or `ED25519` |
| `days_valid` | `int` | `3650` | Validity period in days (1–36500) |
| `valid_from` | `datetime \| None` | `None` | Explicit UTC start; `None` = now |

### `ClientConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `common_name` | `str` | — | Certificate CN |
| `serial_type` | `CertType` | `SERVICE` | Certificate category |
| `key_size` | `int` | `3072` | RSA key length (2048–8192; ignored for EC / Ed25519) |
| `key_algorithm` | `KeyAlgorithm` | `EC_P384` | `EC_P384`, `EC_P256`, `RSA` or `ED25519` |
| `days_valid` | `int` | `365` | Validity period (1–36500; clamped to the CA's expiry) |
| `email` | `EmailStr \| None` | `None` | `emailAddress` Subject attribute |
| `is_server_cert` | `bool` | `True` | Adds ServerAuth EKU + CN as DNS SAN |
| `is_client_cert` | `bool` | `False` | Adds ClientAuth EKU |
| `san_dns` | `list[str] \| None` | `None` | Extra DNS Subject Alternative Names |
| `san_ip` | `list[str] \| None` | `None` | IP address SANs |
| `name` | `str \| None` | `None` | Override output file base name (letters, digits, `.`, `-`, `_`; no leading dot) |

### `CertType`

| Value | String | Description |
|---|---|---|
| `CertType.CA` | `"CA"` | Root or intermediate CA |
| `CertType.USER` | `"USR"` | User / human certificate |
| `CertType.SERVICE` | `"SVC"` | Service / server certificate |
| `CertType.DEVICE` | `"DEV"` | IoT / device certificate |
| `CertType.INTERNAL` | `"INT"` | Internal infrastructure certificate |

---

## Storage Backends

### `LocalStorage` (sync)

```python
from tiny_ca.storage.local_storage import LocalStorage
storage = LocalStorage(base_folder="./pki")
```

```
./pki/
└── [cert_path/]
    └── <uuid>/
        ├── nginx.pem    ← x509.Certificate        (0644)
        ├── nginx.key    ← private key             (0600)
        └── nginx.csr    ← CSR                     (0644)
```

- Private keys are written with mode `0600`.  They are **unencrypted unless**
  `base_encryption_algorithm=BestAvailableEncryption(password)` is passed — a
  warning is logged once per storage instance otherwise.
- `file_name`, `cert_path` and `uuid_str` are validated: absolute paths, `..`
  segments and backslashes raise `InvalidPathError`.
- Without `is_overwrite=True` files are created with `O_EXCL`, so an existing
  file is never replaced.

### `AsyncLocalStorage` (async)

Drop-in async replacement — same constructor, same layout and the same
security properties; blocking I/O runs in worker threads.

---

## Database Adapters

```python
# Sync
db = SyncDBHandler(db_url="sqlite:///pki.db")
db = SyncDBHandler(db_url="postgresql+psycopg2://user:pass@host/pki")

# Async
db = AsyncDBHandler(db_url="sqlite+aiosqlite:///pki.db")
db = AsyncDBHandler(db_url="postgresql+asyncpg://user:pass@host/pki")
await db._db.init_db()
```

### `BaseDB` contract

| Method | Description |
|---|---|
| `get_by_serial(serial)` | Fetch any record by serial number |
| `get_by_name(cn)` | Fetch active VALID record by CN |
| `register_cert_in_db(cert, uuid, key_type)` | Persist a new certificate |
| `revoke_certificate(serial, reason)` | Mark as revoked (RFC 5280) |
| `get_revoked_certificates()` | Yield rows for CRL generation |
| `list_all(status, key_type, limit, offset)` | Paginated listing with filters |
| `get_expiring(within_days)` | VALID certs expiring within N days |
| `delete_by_uuid(uuid)` | Hard-delete a record |
| `update_status_expired()` | Bulk-mark stale VALID records as EXPIRED |

Read methods (and `update_status_expired`) raise `DBOperationError` on any
database failure instead of returning `None` / an empty list — a CA must fail
closed.  `register_cert_in_db` returns `False` on failure; the managers turn
that into `DBOperationError` and remove the artefacts they wrote.  Datetimes
are stored as naive UTC (`DateTime` columns without time zone), which keeps
PostgreSQL / asyncpg happy.

---

## Serial Number Encoding

`SerialWithEncoding` packs three fields into a 160-bit integer (RFC 5280):

```
┌──────────────┬──────────────────────┬────────────────────┐
│  16-bit type │  80-bit name         │  64-bit random     │
│  prefix      │  (up to 10 chars)    │  (secrets.randbits)│
└──────────────┴──────────────────────┴────────────────────┘
```

```python
from tiny_ca.utils.serial_generator import SerialWithEncoding
from tiny_ca.const import CertType

serial = SerialWithEncoding.generate("nginx", CertType.SERVICE)
cert_type, name = SerialWithEncoding.parse(serial)
# cert_type == CertType.SERVICE, name == "nginx"
```

Non-ASCII characters are stored as `?`, so a Cyrillic CN can never overflow
into the type prefix.  The top bit is always zero, so the DER encoding fits the
20-octet limit of RFC 5280.

---

## Error Reference

| Exception | When raised | Resolution |
|---|---|---|
| `DBNotInitedError` | `db_handler is None` | Pass `db_handler` to the manager |
| `NotUniqueCertOwner` | CN conflict, `is_overwrite=False` | Use `is_overwrite=True` |
| `CertNotFound` | `renew`/`rotate` for unknown serial | Verify the serial exists |
| `ValidationCertError` | Bad issuer, expired, invalid signature | Check cert origin and CA |
| `InvalidRangeTimeCertificate` | `not_after` already in the past | Fix `valid_from` or `days_valid` |
| `FileAlreadyExists` | File exists, `is_overwrite=False` | Use `is_overwrite=True` |
| `NotExistCertFile` | CA PEM path missing | Check the file path |
| `IsNotFile` | CA PEM path is a directory | Provide a file, not a directory |
| `WrongType` | Unsupported file extension | Use `.pem`, `.key`, or `.csr` |
| `ErrorLoadCert` | PEM deserialisation failed | Check file format and integrity |
| `DBOperationError` | Registry could not be read / written | Check the database; nothing was trusted or published |
| `CertRevocationError` | Rotation/renewal could not revoke the old cert | Retry; the replacement was rolled back |
| `InvalidPathError` | Storage path would escape `base_folder` | Use plain names / relative sub-paths |
| `CertificateRevokedError` | Renew / co-sign of a revoked cert, delete of a revoked unexpired cert | Issue a new certificate; keep revoked rows until they expire |
| `NameConstraintViolation` | A name is outside the issuer's `NameConstraints` | Use a permitted name or another issuing CA |
| `SignerError` | External signer (HSM / KMS) failed or returned a bad signature | Check the token, PIN, key label and that the key matches the CA certificate |
| `AuditLogError` | Audit entry could not be written, or verification failed | Treat as a security incident: the operation took effect but is not recorded |

---

## FAQ

**Can I use an existing CA?**
Yes — load it with `CAFileLoader` or `AsyncCAFileLoader`.

**What's the difference between `renew` and `rotate`?**
`renew` keeps the key pair and extends validity. `rotate` generates a new key. Both revoke the old cert with reason `superseded`.

**Why does `verify_certificate` reject a certificate signed by my CA?**
Since 0.3.0 a certificate issued directly by the CA must also be present in the
registry — otherwise its revocation status is unknown.  Certificates created
with older versions via `renew` / `cosign` were not registered; re-issue them.

**Why are my new keys EC instead of RSA after upgrading to 1.0?**
1.0 defaults to ECDSA P-384 with SHA-384.  Pass
`key_algorithm=KeyAlgorithm.RSA` (and `key_size=`) where RSA is required.
Existing CAs keep their algorithm; their signature digest now follows the key
size (SHA-384 for RSA ≥ 3072).  See the 1.0.0 "Breaking changes" in
[CHANGELOG.md](CHANGELOG.md).

**How do I see the library's logs?**
`tiny_ca` only attaches a `NullHandler`; configure the `"TinyCA"` logger in your
application, e.g. `logging.getLogger("TinyCA").setLevel(logging.INFO)`.

**How do I schedule CRL regeneration?**
Use APScheduler or any cron solution:
```python
scheduler.add_job(mgr.generate_crl, "cron", day_of_week="mon", hour=0)
```

**Can I use a custom storage backend (S3, Redis)?**
Yes — subclass `BaseStorage` and implement `save_certificate` and `delete_certificate_folder`.

**How do I protect the CA private key with a password?**
```python
loader = CAFileLoader(ca_cert_path="ca.pem", ca_key_path="ca.key",
                      ca_key_password=b"passphrase")
```

---

## Migrating from Other CAs

### From OpenSSL

```bash
openssl x509 -in ca.crt -out ca.pem -outform PEM
openssl rsa  -in ca.key -out ca-key.pem -outform PEM
```
```python
loader = CAFileLoader(ca_cert_path="ca.pem", ca_key_path="ca-key.pem")
mgr.factory = CertificateFactory(loader)
```

### From Easy-RSA / CFSSL

Both output standard PEM files — follow the OpenSSL migration steps.

---

## Benchmark Results

*Linux 6.17, Python 3.11.15, 32-core CPU, NVMe SSD. 5 iterations each.*

| Operation | Sync | Async |
|---|---|---|
| CA creation (2048-bit) | 0.037 s | 0.067 s |
| CA creation (4096-bit) | 0.317 s | 0.411 s |
| Leaf issuance (2048-bit) | 0.055 s | 0.052 s |
| Leaf issuance (4096-bit) | 0.476 s | 0.712 s |
| CRL generation | 0.001 s | 0.002 s |
| Certificate verification | 0.0003 s | 0.0008 s |
| PKCS#12 export | 0.0005 s | 0.0006 s |

Key generation dominates issuance time. For >1 000 certs/hour use PostgreSQL, the async API, and connection pooling.

---

## Project Structure

```
tiny_ca/
├── const.py                        # CertType, KeyAlgorithm, secure defaults / bounds
├── exc.py                          # all custom exceptions
├── signing.py                      # CASigner, KeySigner, Pkcs11Signer, sign_builder
├── audit.py                        # AuditLog — signed, hash-chained audit log
├── settings.py                     # DEFAULT_LOGGER
├── ca_factory/
│   ├── factory.py                  # CertificateFactory — all crypto
│   └── utils/
│       ├── file_loader.py          # CAFileLoader + ICALoader Protocol
│       ├── afile_loader.py         # AsyncCAFileLoader
│       ├── signer_loader.py        # SignerCALoader + ISignerCALoader Protocol
│       ├── name_constraints.py     # NameConstraints building / enforcement
│       ├── life_time.py            # CertLifetime
│       └── serial.py               # CertSerialParser
├── db/
│   ├── base_db.py                  # BaseDB — 9 abstract methods
│   ├── models.py                   # CertificateRecord ORM model
│   ├── const.py                    # RevokeStatus, CertificateStatus
│   ├── sync_db_manager.py          # SyncDBHandler
│   └── async_db_manager.py         # AsyncDBHandler
├── managers/
│   ├── sync_lifecycle_manager.py   # CertLifecycleManager (20+ ops)
│   └── async_lifecycle_manager.py  # AsyncCertLifecycleManager
├── models/
│   └── certificate.py              # CAConfig, ClientConfig, NameConstraintsConfig, CertificateDetails
├── storage/
│   ├── base_storage.py             # BaseStorage ABC
│   ├── const.py                    # CryptoObject type alias
│   ├── local_storage.py            # LocalStorage
│   └── async_local_storage.py      # AsyncLocalStorage
└── utils/
    └── serial_generator.py         # SerialWithEncoding
```

---

## Security Model

tiny-ca gives you the building blocks of a high-assurance PKI:
- an HSM-held CA key;
- strong defaults;
- certificate policies and name constraints;
- fail-closed revocation checks;
- a signed audit trail.

The library itself is **not** certified against any national, NATO or
Common Criteria scheme.  It relies on the `cryptography` package (OpenSSL),
which is not a FIPS 140-3 validated module unless you build it against
one.  Accreditation also covers things outside a library: the operating
environment, role separation and dual control for CA operations, key
ceremonies, physical security, and a published CP/CPS.  Plan those
separately.

Known limits:
- No OCSP responder.  Publish CRLs (`generate_crl`) and point relying
  parties at them with `crl_distribution_points`.
- Name constraints cover DNS, IP and e-mail names.  Other types fail closed.
- The audit log is written after an operation completes.  Its tail is
  protected only by publishing the head hash elsewhere.  It has no
  inter-process lock on Windows.
- Without an HSM, the CA key is a file.  Keep it encrypted
  (`base_encryption_algorithm`) on an offline or tightly controlled host.

## Security Policy

Do **not** open public issues for security vulnerabilities. Email the maintainer (see GitHub profile). Acknowledgement within 48 hours; public advisory only after a fix is available.

---

## License

[MIT](LICENSE) © 2025 Denis Shchutskyi

| Dependency | License |
|---|---|
| cryptography | BSD 3-Clause |
| SQLAlchemy | MIT |
| Pydantic | MIT |
| aiosqlite | MIT |
| python-pkcs11 (optional, `hsm`) | MIT |
