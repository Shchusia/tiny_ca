# tiny_ca

[![Coverage Status](https://img.shields.io/badge/%20Python%20Versions-%3E%3D3.11-informational)](https://github.com/Shchusia/tiny_ca)
[![Coverage Status](https://coveralls.io/repos/github/Shchusia/tiny_ca/badge.svg?branch=feature/docs)](https://coveralls.io/github/Shchusia/tiny_ca?branch=feature/docs)

[![Coverage Status](https://img.shields.io/badge/Version-0.1.2-informational)](https://pypi.org/project/tiny_ca/)
[![Coverage Status](https://img.shields.io/badge/Docs-passed-green)](https://shchusia.github.io/tiny_ca/)

A lightweight Python library for managing the full lifecycle of X.509 certificates — from bootstrapping a self-signed root CA to issuing, revoking, and rotating end-entity certificates, generating CRLs, and persisting all artefacts to local storage backed by a relational database.

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [1. Bootstrap a Self-Signed Root CA](#1-bootstrap-a-self-signed-root-ca)
  - [2. Issue an End-Entity Certificate](#2-issue-an-end-entity-certificate)
  - [3. Revoke a Certificate](#3-revoke-a-certificate)
  - [4. Generate a CRL](#4-generate-a-crl)
  - [5. Verify a Certificate](#5-verify-a-certificate)
  - [6. Rotate a Certificate](#6-rotate-a-certificate)
  - [7. Async Usage](#7-async-usage)
- [Configuration Models](#configuration-models)
- [Storage Backends](#storage-backends)
- [Database Adapters](#database-adapters)
- [Serial Number Encoding](#serial-number-encoding)
- [Error Reference](#error-reference)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)

---

## Features

- **Self-signed CA bootstrap** — generate a root CA certificate and key in one call.
- **End-entity certificate issuance** — server, client, device, user, and service certificates with SANs (DNS + IP).
- **Certificate revocation** — mark certificates as revoked in the database with RFC 5280 reason codes.
- **CRL generation** — build and sign a Certificate Revocation List from current revocation records.
- **Certificate verification** — validate issuer, validity window, signature, and revocation status.
- **Certificate rotation** — atomically revoke an old certificate and issue its replacement.
- **Pluggable storage** — `LocalStorage` and `AsyncLocalStorage` write PEM/key/CSR/CRL files to a configurable directory tree.
- **Pluggable database** — `SyncDBHandler` (SQLAlchemy sync) and `AsyncDBHandler` (SQLAlchemy async/aiosqlite) back the certificate registry.
- **Sync and async APIs** — `CertLifecycleManager` (sync) and `AsyncCertLifecycleManager` (async) with identical feature sets.
- **Smart serial numbers** — `SerialWithEncoding` packs a CertType prefix + name fragment + UUID randomness into a single 160-bit integer; fully RFC 5280-compliant.

---

## Architecture Overview

```
CertLifecycleManager / AsyncCertLifecycleManager
        │
        ├── CertificateFactory          ← cryptographic operations only
        │       ├── CAFileLoader / AsyncCAFileLoader   ← load CA from PEM files
        │       └── CertLifetime / CertSerialParser    ← validity & serial helpers
        │
        ├── BaseStorage
        │       ├── LocalStorage        ← sync filesystem backend
        │       └── AsyncLocalStorage   ← async filesystem backend
        │
        └── BaseDB
                ├── SyncDBHandler       ← SQLAlchemy sync
                └── AsyncDBHandler      ← SQLAlchemy async (aiosqlite)
```

Every component is injected at construction time — no global state, easy to test.

---

## Installation

```bash
pip install tiny_ca
# async support (aiosqlite + aiofiles)
pip install tiny_ca[async]
```

Dependencies: `cryptography`, `sqlalchemy`, `pydantic`.
Optional: `aiosqlite`, `aiofiles` (async backends).

---

## Quick Start

### 1. Bootstrap a Self-Signed Root CA

```python
from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
from tiny_ca.models.certtificate import CAConfig
from tiny_ca.storage.local_storage import LocalStorage
from tiny_ca.db.sync_db_manager import SyncDBHandler

storage = LocalStorage(base_folder="./pki")
db = SyncDBHandler(db_url="sqlite:///pki.db")

mgr = CertLifecycleManager(storage=storage, db_handler=db)

config = CAConfig(
    common_name="My Internal CA",
    organization="ACME Corp",
    country="UA",
    key_size=4096,
    days_valid=3650,
)

cert_path, key_path = mgr.create_self_signed_ca(config)
print(f"CA certificate: {cert_path}")
print(f"CA private key: {key_path}")
```

### 2. Issue an End-Entity Certificate

After bootstrapping the CA you need to load it back and attach a `CertificateFactory`:

```python
from tiny_ca.ca_factory.utils.file_loader import CAFileLoader
from tiny_ca.ca_factory.factory import CertificateFactory
from tiny_ca.models.certtificate import ClientConfig
from tiny_ca.const import CertType

loader = CAFileLoader(
    ca_cert_path="./pki/<uuid>/ca.pem",
    ca_key_path="./pki/<uuid>/ca.key",
)
mgr.factory = CertificateFactory(loader)

svc_config = ClientConfig(
    common_name="nginx.internal",
    serial_type=CertType.SERVICE,
    key_size=2048,
    days_valid=365,
    is_server_cert=True,
    san_dns=["nginx.internal", "www.nginx.internal"],
    san_ip=["192.168.1.10"],
)

cert, key, csr = mgr.issue_certificate(svc_config, cert_path="services")
print(f"Issued: {cert.serial_number}")
```

### 3. Revoke a Certificate

```python
from cryptography import x509

success = mgr.revoke_certificate(
    serial=cert.serial_number,
    reason=x509.ReasonFlags.key_compromise,
)
print("Revoked:", success)
```

### 4. Generate a CRL

```python
crl = mgr.generate_crl(days_valid=7)
# Written to <base_folder>/crl.pem automatically
```

### 5. Verify a Certificate

```python
from tiny_ca.exc import ValidationCertError

try:
    mgr.verify_certificate(cert)
    print("Certificate is valid")
except ValidationCertError as e:
    print(f"Validation failed: {e}")
```

### 6. Rotate a Certificate

```python
new_cert, new_key, new_csr = mgr.rotate_certificate(
    serial=cert.serial_number,
    config=svc_config,
)
print(f"Rotated to serial: {new_cert.serial_number}")
```

### 7. Async Usage

All operations are available as `async`/`await` via `AsyncCertLifecycleManager`:

```python
import asyncio
from tiny_ca.managers.async_lifecycle_manager import AsyncCertLifecycleManager
from tiny_ca.storage.async_local_storage import AsyncLocalStorage
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.models.certtificate import CAConfig, ClientConfig
from tiny_ca.const import CertType

async def main():
    storage = AsyncLocalStorage(base_folder="./pki_async")
    db = AsyncDBHandler(db_url="sqlite+aiosqlite:///pki_async.db")
    await db._db.init_db()

    mgr = AsyncCertLifecycleManager(storage=storage, db_handler=db)

    # Bootstrap CA
    cert_path, key_path = await mgr.create_self_signed_ca(
        CAConfig(common_name="Async CA", organization="ACME", country="UA",
                 key_size=2048, days_valid=3650)
    )

    # Attach factory (after loading the CA)
    from tiny_ca.ca_factory.utils.afile_loader import AsyncCAFileLoader
    from tiny_ca.ca_factory.factory import CertificateFactory

    loader = await AsyncCAFileLoader.create(cert_path.parent / "ca.pem",
                                            cert_path.parent / "ca.key")
    mgr.factory = CertificateFactory(loader)

    # Issue
    cert, key, csr = await mgr.issue_certificate(
        ClientConfig(common_name="modules.internal", serial_type=CertType.SERVICE,
                     key_size=2048, days_valid=365, is_server_cert=True)
    )
    print("Issued:", cert.serial_number)

asyncio.run(main())
```

---

## Configuration Models

Both models are Pydantic `BaseModel` instances — all fields are validated on construction.

### `CAConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `common_name` | `str` | — | CA Common Name (CN) |
| `organization` | `str` | — | Organization (O) |
| `country` | `str` | — | Two-letter ISO country code |
| `key_size` | `int` | `2048` | RSA key length in bits |
| `days_valid` | `int` | `3650` | Validity period in days |

### `ClientConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `common_name` | `str` | — | Certificate CN |
| `serial_type` | `CertType` | `SERVICE` | Certificate category |
| `key_size` | `int` | `2048` | RSA key length |
| `days_valid` | `int` | `365` | Validity period |
| `email` | `str \| None` | `None` | Optional emailAddress Subject attribute |
| `is_server_cert` | `bool` | `False` | Adds ServerAuth EKU + DNS SAN from CN |
| `is_client_cert` | `bool` | `False` | Adds ClientAuth EKU |
| `san_dns` | `list[str] \| None` | `None` | Extra DNS Subject Alternative Names |
| `san_ip` | `list[str] \| None` | `None` | IP address SANs |
| `name` | `str \| None` | `None` | Override output file base name |

### `CertType` enum

| Value | Description |
|---|---|
| `CA` | Root or intermediate CA |
| `USER` | User / human certificate |
| `SERVICE` | Service / server certificate |
| `DEVICE` | IoT / device certificate |
| `INTERNAL` | Internal infrastructure certificate |

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

File layout:
```
./pki/
└── [cert_path/]
    └── <uuid>/
        ├── service.pem    # x509.Certificate
        ├── service.key    # RSA private key
        └── service.csr    # CertificateSigningRequest
```

### `AsyncLocalStorage` (async)

Drop-in async replacement for `LocalStorage` — same constructor, same layout, all I/O methods are `async`.

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
await db._db.init_db()  # create schema on first run
```

Both implement `BaseDB`:

| Method | Description |
|---|---|
| `get_by_serial(serial)` | Fetch record by X.509 serial number |
| `get_by_name(common_name)` | Fetch active VALID record by CN |
| `register_cert_in_db(cert, uuid, key_type)` | Persist new certificate |
| `revoke_certificate(serial, reason)` | Mark certificate as revoked |
| `get_revoked_certificates()` | Yield records for CRL generation |

---

## Serial Number Encoding

`SerialWithEncoding` packs three fields into a single 160-bit integer:

```
[ 16-bit prefix ][ 80-bit name ][ 64-bit random ]
```

- **prefix** — 2-byte ASCII code of the `CertType` (e.g. `"SV"` for `SERVICE`).
- **name** — up to 10 ASCII characters from the CN, zero-padded.
- **random** — lower 64 bits of a fresh `uuid.uuid4()`.

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

| Exception | When raised |
|---|---|
| `DBNotInitedError` | A DB-required operation is called but `db_handler` is `None` |
| `NotUniqueCertOwner` | CN conflict detected and `is_overwrite=False` |
| `CertNotFound` | `rotate_certificate` called for a non-existent serial |
| `ValidationCertError` | Issuer mismatch, expired, or signature verification failure |
| `InvalidRangeTimeCertificate` | Computed `not_after` is already in the past |
| `FileAlreadyExists` | Target file exists and `is_overwrite=False` |
| `NotExistCertFile` | CA PEM file path does not exist |
| `IsNotFile` | CA PEM path exists but is not a regular file |
| `WrongType` | CA PEM file has an unsupported extension |
| `ErrorLoadCert` | PEM deserialisation failed |

---

## Running Tests

```bash
pip install pytest pytest-cov aiosqlite aiofiles
pytest tests/ --cov=tiny_ca --cov-report=term-missing
```

---

## Project Structure

```
tiny_ca/
├── ca_factory/
│   ├── factory.py              # CertificateFactory — crypto generation
│   └── utils/
│       ├── file_loader.py      # CAFileLoader + ICALoader protocol
│       ├── afile_loader.py     # AsyncCAFileLoader
│       ├── life_time.py        # CertLifetime — validity window helpers
│       └── serial.py           # CertSerialParser
├── db/
│   ├── base_db.py              # BaseDB ABC
│   ├── models.py               # CertificateRecord ORM model
│   ├── const.py                # RevokeStatus, CertificateStatus
│   ├── sync_db_manager.py      # SyncDBHandler + DatabaseManager
│   └── async_db_manager.py     # AsyncDBHandler + async DatabaseManager
├── managers/
│   ├── sync_lifecycle_manager.py   # CertLifecycleManager
│   └── async_lifecycle_manager.py  # AsyncCertLifecycleManager
├── models/
│   └── certtificate.py         # CAConfig, ClientConfig, CertificateInfo
├── storage/
│   ├── base_storage.py         # BaseStorage ABC
│   ├── const.py                # CryptoObject type alias
│   ├── local_storage.py        # LocalStorage + _CertSerializer
│   └── async_local_storage.py  # AsyncLocalStorage
├── utils/
│   └── serial_generator.py     # SerialGenerator, SerialWithEncoding, _PrefixRegistry
├── const.py                    # CertType enum
├── exc.py                      # All custom exceptions
└── settings.py                 # DEFAULT_LOGGER
```
