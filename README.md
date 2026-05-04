# tiny_ca

[![Python](https://img.shields.io/badge/Python-%3E%3D3.11-informational)](https://github.com/Shchusia/tiny_ca)
[![Coverage](https://img.shields.io/badge/Coverage-100%25-brightgreen)](https://github.com/Shchusia/tiny_ca)
[![Version](https://img.shields.io/badge/Version-0.1.3-informational)](https://pypi.org/project/tiny_ca/)
[![Docs](https://img.shields.io/badge/Docs-passing-green)](https://shchusia.github.io/tiny_ca/)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

A lightweight Python library for managing the full lifecycle of X.509 certificates — from bootstrapping a self-signed root CA to issuing, revoking, rotating, renewing, and co-signing end-entity certificates, generating and verifying CRLs, exporting PKCS#12 bundles, and issuing intermediate CAs — all backed by pluggable sync/async storage and database adapters.

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [1. Bootstrap a Root CA](#1-bootstrap-a-root-ca)
  - [2. Issue a Leaf Certificate](#2-issue-a-leaf-certificate)
  - [3. Renew a Certificate (same key)](#3-renew-a-certificate-same-key)
  - [4. Rotate a Certificate (new key)](#4-rotate-a-certificate-new-key)
  - [5. Revoke a Certificate](#5-revoke-a-certificate)
  - [6. Generate and Verify a CRL](#6-generate-and-verify-a-crl)
  - [7. Issue an Intermediate CA](#7-issue-an-intermediate-ca)
  - [8. Export PKCS#12](#8-export-pkcs12)
  - [9. Co-sign a Third-Party Certificate](#9-co-sign-a-third-party-certificate)
  - [10. Inspect a Certificate](#10-inspect-a-certificate)
  - [11. List and Monitor Certificates](#11-list-and-monitor-certificates)
  - [12. Async Usage](#12-async-usage)
- [Configuration Models](#configuration-models)
- [Storage Backends](#storage-backends)
- [Database Adapters](#database-adapters)
- [Serial Number Encoding](#serial-number-encoding)
- [Error Reference](#error-reference)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)
- [Design Notes](#design-notes)

---

## Features

| Category | Capability |
|---|---|
| **CA bootstrap** | Self-signed root CA and intermediate (sub) CA issuance |
| **Issuance** | Leaf certificates with SANs (DNS + IP), EKU, email attribute |
| **Lifecycle** | Revoke, renew (same key), rotate (new key), hard-delete |
| **CRL** | Build, sign, verify Certificate Revocation Lists |
| **Inspection** | Structured `CertificateDetails` snapshot from any `x509.Certificate` |
| **Export** | PKCS#12 (`.p12`/`.pfx`) bundles with CA chain included |
| **Co-signing** | Re-sign a third-party certificate under this CA |
| **Chain** | Build `[leaf, ca]` fullchain ready for nginx/envoy |
| **Monitoring** | List certs with filters, find expiring-soon, bulk-expire stale records |
| **Storage** | `LocalStorage` (sync) and `AsyncLocalStorage` (async, aiofiles) |
| **Database** | `SyncDBHandler` (SQLAlchemy) and `AsyncDBHandler` (aiosqlite) |
| **API parity** | `CertLifecycleManager` and `AsyncCertLifecycleManager` are feature-identical |
| **Serial numbers** | `SerialWithEncoding` — 160-bit RFC 5280-compliant, type-prefixed, name-encoded |
| **Test coverage** | 100 % line and branch coverage |

---

## Architecture Overview

```
CertLifecycleManager / AsyncCertLifecycleManager   ← application entry-point
        │
        ├── CertificateFactory                      ← crypto-only, no I/O
        │       ├── ICALoader (Protocol)
        │       │       ├── CAFileLoader            ← sync PEM file loader
        │       │       └── AsyncCAFileLoader       ← async PEM file loader
        │       ├── CertLifetime                    ← validity window helpers
        │       ├── CertSerialParser                ← read serials from certs
        │       └── SerialWithEncoding              ← encode/decode serials
        │
        ├── BaseStorage (ABC)
        │       ├── LocalStorage                    ← sync filesystem
        │       └── AsyncLocalStorage               ← async filesystem (aiofiles)
        │
        └── BaseDB (ABC)
                ├── SyncDBHandler                   ← SQLAlchemy sync
                └── AsyncDBHandler                  ← SQLAlchemy async (aiosqlite)
```

Every component is injected at construction time — no global singletons, trivially testable.

---

## Installation

```bash
# Core (sync only)
pip install tiny_ca

# With async support
pip install tiny_ca[async]
```

**Core dependencies:** `cryptography`, `sqlalchemy`, `pydantic`
**Async extras:** `aiosqlite`, `aiofiles`

---

## Quick Start

### 1. Bootstrap a Root CA

```python
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
print(f"CA cert: {cert_path}")
print(f"CA key:  {key_path}")
```

After bootstrapping, attach the factory so the manager can issue certificates:

```python
from tiny_ca.ca_factory.utils.file_loader import CAFileLoader
from tiny_ca.ca_factory.factory import CertificateFactory

loader = CAFileLoader(ca_cert_path=cert_path, ca_key_path=key_path)
mgr.factory = CertificateFactory(loader)
```

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
print(f"Issued serial: {cert.serial_number}")
```

### 3. Renew a Certificate (same key)

Renew keeps the existing public key — only the validity window and serial number change.
Use this when the private key has not been compromised.

```python
renewed_cert = mgr.renew_certificate(serial=cert.serial_number, days_valid=365)
print(f"Renewed serial: {renewed_cert.serial_number}")
```

### 4. Rotate a Certificate (new key)

Rotation atomically revokes the old certificate and issues a replacement with a fresh key pair.

```python
new_cert, new_key, new_csr = mgr.rotate_certificate(
    serial=cert.serial_number,
    config=ClientConfig(
        common_name="nginx.internal",
        serial_type=CertType.SERVICE,
        days_valid=365,
        is_server_cert=True,
    ),
)
print(f"Rotated to serial: {new_cert.serial_number}")
```

### 5. Revoke a Certificate

```python
from cryptography import x509

ok = mgr.revoke_certificate(
    serial=cert.serial_number,
    reason=x509.ReasonFlags.key_compromise,
)
print("Revoked:", ok)
```

### 6. Generate and Verify a CRL

```python
# Generate — written to <base_folder>/crl.pem
crl = mgr.generate_crl(days_valid=7)

# Verify the CRL's issuer, signature, and expiry
mgr.verify_crl(crl)     # raises ValidationCertError on failure
print("CRL is valid, next update:", crl.next_update_utc)
```

### 7. Issue an Intermediate CA

```python
sub_ca_cert, sub_ca_key = mgr.issue_intermediate_ca(
    common_name="Issuing CA",
    key_size=4096,
    days_valid=1825,      # 5 years
    path_length=0,        # can only sign leaf certs, not further sub-CAs
    organization="ACME Corp",
    country="UA",
    cert_path="intermediate",
)
```

### 8. Export PKCS#12

Creates a `.p12` bundle containing the certificate, its private key, and the CA in the chain.
Ready for import into Windows certificate stores, macOS Keychain, or Java keystores.

```python
p12_bytes = mgr.export_pkcs12(
    cert=cert,
    private_key=key,
    password=b"strong-passphrase",  # None for unencrypted
    name="nginx.internal",
)
with open("nginx.p12", "wb") as f:
    f.write(p12_bytes)
```

### 9. Co-sign a Third-Party Certificate

Re-signs an existing certificate (e.g. from a partner CA) under your CA's key,
preserving the original Subject, public key, and extensions.

```python
from cryptography import x509

third_party_cert = x509.load_pem_x509_certificate(open("partner.pem", "rb").read())

cosigned = mgr.cosign_certificate(
    cert=third_party_cert,
    days_valid=365,      # None keeps the original validity window
)
```

### 10. Inspect a Certificate

Returns a structured, serialisable `CertificateDetails` snapshot — no `cryptography` objects leak out.

```python
details = mgr.inspect_certificate(cert)

print(details.common_name)          # "nginx.internal"
print(details.san_dns)              # ["nginx.internal", "www.nginx.internal"]
print(details.san_ip)               # ["192.168.1.10"]
print(details.fingerprint_sha256)   # "AB:CD:..."
print(details.public_key_size)      # 2048
print(details.is_ca)                # False
```

Get the full chain as `[leaf, ca_cert]` in PEM order (nginx `ssl_certificate` format):

```python
chain = mgr.get_cert_chain(cert)
fullchain_pem = b"".join(
    c.public_bytes(serialization.Encoding.PEM) for c in chain
)
```

### 11. List and Monitor Certificates

```python
# Paginated list with optional filters
records = mgr.list_certificates(
    status="valid",
    key_type="service",
    limit=50,
    offset=0,
)

# Certificates expiring within 30 days
expiring = mgr.get_expiring_soon(within_days=30)
for r in expiring:
    print(r.common_name, r.not_valid_after)

# Bulk-mark expired records (run periodically)
updated = mgr.refresh_expired_statuses()
print(f"Marked {updated} certificates as expired")

# Hard-delete: removes DB record and artefact folder
deleted = mgr.delete_certificate(serial=cert.serial_number)
```

### 12. Async Usage

All operations are available via `AsyncCertLifecycleManager` with identical signatures:

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

  # Bootstrap
  cert_path, key_path = await mgr.create_self_signed_ca(
    CAConfig(common_name="Async CA", organization="ACME", country="UA",
             key_size=2048, days_valid=3650)
  )

  # Attach factory
  from tiny_ca.ca_factory.utils.afile_loader import AsyncCAFileLoader
  from tiny_ca.ca_factory.factory import CertificateFactory

  loader = await AsyncCAFileLoader.create(cert_path, key_path)
  mgr.factory = CertificateFactory(loader)

  # Issue
  cert, key, csr = await mgr.issue_certificate(
    ClientConfig(common_name="api.internal", serial_type=CertType.SERVICE,
                 key_size=2048, days_valid=365, is_server_cert=True)
  )

  # Inspect
  details = await mgr.inspect_certificate(cert)
  print(details.fingerprint_sha256)

  # Export
  p12 = await mgr.export_pkcs12(cert, key, password=b"secret")


asyncio.run(main())
```

---

## Configuration Models

All models are Pydantic `BaseModel` — fields are validated on construction.

### `CAConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `common_name` | `str` | `"Internal CA"` | CA Common Name (CN) |
| `organization` | `str` | `"My Company"` | Organization (O) |
| `country` | `str` | `"UA"` | Two-letter ISO 3166-1 alpha-2 code |
| `key_size` | `int` | `2048` | RSA key length in bits |
| `days_valid` | `int` | `3650` | Validity period in days |
| `valid_from` | `datetime \| None` | `None` | Explicit start (UTC); `None` = now |

### `ClientConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `common_name` | `str` | `"Internal CA"` | Certificate CN |
| `serial_type` | `CertType` | `CA` | Certificate category |
| `key_size` | `int` | `2048` | RSA key length |
| `days_valid` | `int` | `3650` | Validity period |
| `email` | `EmailStr \| None` | `None` | `emailAddress` Subject attribute |
| `is_server_cert` | `bool` | `True` | Adds ServerAuth EKU + CN as DNS SAN |
| `is_client_cert` | `bool` | `False` | Adds ClientAuth EKU |
| `san_dns` | `list[str] \| None` | `None` | Extra DNS Subject Alternative Names |
| `san_ip` | `list[IPvAnyAddress] \| None` | `None` | IP address SANs |
| `name` | `str \| None` | `None` | Override output file base name |

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
from cryptography.hazmat.primitives import serialization

storage = LocalStorage(
    base_folder="./pki",
    base_encoding=serialization.Encoding.PEM,
    base_private_format=serialization.PrivateFormat.TraditionalOpenSSL,
    base_encryption_algorithm=serialization.NoEncryption(),
)
```

**File layout:**
```
./pki/
└── [cert_path/]
    └── <uuid>/
        ├── nginx.pem    ← x509.Certificate
        ├── nginx.key    ← RSA private key
        └── nginx.csr    ← CertificateSigningRequest
```

### `AsyncLocalStorage` (async)

Drop-in async replacement — same constructor signature, same file layout, all I/O via `aiofiles`.

---

## Database Adapters

### `SyncDBHandler`

```python
from tiny_ca.db.sync_db_manager import SyncDBHandler

db = SyncDBHandler(db_url="sqlite:///pki.db")
# PostgreSQL: "postgresql+psycopg2://user:pass@host/dbname"
```

### `AsyncDBHandler`

```python
from tiny_ca.db.async_db_manager import AsyncDBHandler

db = AsyncDBHandler(db_url="sqlite+aiosqlite:///pki.db")
await db._db.init_db()   # create schema on first run
```

### `BaseDB` contract

| Method | Description |
|---|---|
| `get_by_serial(serial)` | Fetch any record by integer serial number |
| `get_by_name(cn)` | Fetch active VALID record by Common Name |
| `register_cert_in_db(cert, uuid, key_type)` | Persist new certificate |
| `revoke_certificate(serial, reason)` | Mark certificate as revoked (RFC 5280) |
| `get_revoked_certificates()` | Yield rows for CRL generation |
| `list_all(status, key_type, limit, offset)` | Paginated listing with filters |
| `get_expiring(within_days)` | VALID certs expiring within N days |
| `delete_by_uuid(uuid)` | Hard-delete a record by storage UUID |
| `update_status_expired()` | Bulk-mark stale VALID records as EXPIRED |

---

## Serial Number Encoding

`SerialWithEncoding` packs three fields into a single 160-bit integer (RFC 5280 compliant):

```
┌──────────────┬────────────────────┬────────────────────┐
│  16-bit type │   80-bit name      │   64-bit random    │
│  prefix      │   (up to 10 chars) │   (UUID fragment)  │
└──────────────┴────────────────────┴────────────────────┘
```

- **prefix** — 2-byte ASCII representation of `CertType` (e.g. `0x5356` for `SERVICE`).
- **name** — up to 10 ASCII characters from the CN, zero-padded and little-endian.
- **random** — lower 64 bits of `uuid.uuid4()`, providing collision resistance.

```python
from tiny_ca.utils.serial_generator import SerialWithEncoding
from tiny_ca.const import CertType

serial = SerialWithEncoding.generate("nginx", CertType.SERVICE)
cert_type, name = SerialWithEncoding.parse(serial)
# cert_type == CertType.SERVICE
# name == "nginx"
```

---

## Error Reference

| Exception | Raised when |
|---|---|
| `DBNotInitedError` | DB-requiring operation called but `db_handler is None` |
| `NotUniqueCertOwner` | CN conflict detected and `is_overwrite=False` |
| `CertNotFound` | `renew_certificate` or `rotate_certificate` called for unknown serial |
| `ValidationCertError` | Issuer mismatch, expired cert/CRL, or invalid signature |
| `InvalidRangeTimeCertificate` | Computed `not_after` is already in the past |
| `FileAlreadyExists` | Target file exists and `is_overwrite=False` |
| `NotExistCertFile` | CA PEM path does not exist |
| `IsNotFile` | CA PEM path is not a regular file |
| `WrongType` | CA PEM file has an unsupported extension |
| `ErrorLoadCert` | PEM deserialisation failed |

---

## Running Tests

```bash
pip install pytest pytest-cov aiosqlite aiofiles
pytest tests/ --cov=tiny_ca --cov-report=term-missing
```

Coverage target: **100 %** lines and branches across all modules.

---

## Project Structure

```
tiny_ca/
├── ca_factory/
│   ├── factory.py                  # CertificateFactory — all crypto generation
│   └── utils/
│       ├── file_loader.py          # CAFileLoader + ICALoader Protocol
│       ├── afile_loader.py         # AsyncCAFileLoader
│       ├── life_time.py            # CertLifetime — validity window helpers
│       └── serial.py               # CertSerialParser — read serials from certs
├── db/
│   ├── base_db.py                  # BaseDB abstract contract (9 abstract methods)
│   ├── models.py                   # CertificateRecord ORM model
│   ├── const.py                    # RevokeStatus, CertificateStatus
│   ├── sync_db_manager.py          # SyncDBHandler + DatabaseManager
│   └── async_db_manager.py         # AsyncDBHandler + async DatabaseManager
├── managers/
│   ├── sync_lifecycle_manager.py   # CertLifecycleManager (20+ operations)
│   └── async_lifecycle_manager.py  # AsyncCertLifecycleManager (identical API)
├── models/
│   └── certtificate.py             # CAConfig, ClientConfig, CertificateInfo, CertificateDetails
├── storage/
│   ├── base_storage.py             # BaseStorage abstract contract
│   ├── const.py                    # CryptoObject union type alias
│   ├── local_storage.py            # LocalStorage + _CertSerializer
│   └── async_local_storage.py      # AsyncLocalStorage
├── utils/
│   └── serial_generator.py         # ISerialGenerator, SerialGenerator, SerialWithEncoding
├── const.py                        # CertType enum, ALLOWED_CERT_EXTENSIONS
├── exc.py                          # All custom exceptions
└── settings.py                     # DEFAULT_LOGGER, DT_STR_FORMAT
```

---

## Design Notes

### What the code does well

**SOLID adherence is genuine, not decorative.** `CertificateFactory` truly contains zero file I/O and zero SQL — it only knows `cryptography`. `BaseStorage` and `BaseDB` are real abstractions backed by real implementations, not wrappers around a single concrete class. The `ICALoader` Protocol makes it trivial to substitute a test double or an HSM-backed loader without any code change in the factory.

**`SerialWithEncoding` is a standout component.** Encoding CertType prefix + name + UUID randomness into a 160-bit integer is clever and immediately useful — a DBA can identify certificate category from a raw SQL `SELECT` without joining any lookup table. The `_PrefixRegistry` cleanly owns the CertType↔hex mapping and is the only place to change when a new type is added.

**The sync/async symmetry is clean.** `AsyncCertLifecycleManager` wraps CPU-bound crypto in `asyncio.to_thread` and I/O in async storage — the event loop is never blocked. The decision to share `CertificateFactory` (sync crypto) between both managers rather than duplicating it is correct.

**`_CertSerializer` is a well-scoped private helper.** Isolating type-dispatch logic for serialisation into its own class means `LocalStorage` contains only path resolution and file I/O. Adding a new crypto type (e.g. Ed25519 keys) touches one branch in `_CertSerializer` and nothing else.

### What could be improved

**`factory.py` imports `sqlalchemy.Row` at the module level** but only uses it in a type annotation for `build_crl`. This creates a hard SQLAlchemy dependency in what is supposed to be a pure cryptography module. The type annotation should use `Any` or a local `TYPE_CHECKING` guard.

**`renew_certificate` in the lifecycle managers** does `from cryptography import x509 as _x509` inside the method body — a deferred import that exists to avoid a name collision with the parameter. The parameter should be renamed (e.g. `cert_obj`) and the import moved to the top of the file.

**`issue_intermediate_ca` in the lifecycle managers** saves the cert and key with the same `file_name="intermediate_ca"` in two consecutive calls. The second call will silently overwrite the first because `is_overwrite=True`. The key file needs a distinct name (e.g. `"intermediate_ca"` → `.key`, `"intermediate_ca"` → `.pem` — they do get different extensions from `_CertSerializer`, so this is actually fine, but the intent is not obvious from reading the code). A comment would clarify.

**`CertLifecycleManager.get_certificate_status`** reads `cert.not_valid_after` (a naive datetime from the ORM) and handles the `tzinfo is None` case inline. This timezone-normalisation logic belongs in `CertLifetime` or in the ORM model, not scattered across two lifecycle manager files.

**`models.py` has a typo in the filename** (`certtificate.py` — double `t`). Minor but affects discoverability.

**The `README` database adapter table** previously listed only 5 `BaseDB` methods. There are now 9 — the new ones (`list_all`, `get_expiring`, `delete_by_uuid`, `update_status_expired`) were missing from the documentation.
