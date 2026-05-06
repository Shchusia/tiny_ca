# tiny_ca

[![Python](https://img.shields.io/pypi/pyversions/tiny-ca)](https://pypi.org/project/tiny-ca/)
[![PyPI](https://img.shields.io/pypi/v/tiny-ca?color=blue)](https://pypi.org/project/tiny-ca/)

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
- [Security Policy](#security-policy)
- [License](#license)

---

## Features

| Category | Capability |
|---|---|
| **CA bootstrap** | Self-signed root CA and intermediate (sub) CA with configurable `path_length` |
| **Issuance** | Leaf certificates with SANs (DNS + IP), EKU (Server/Client Auth), email attribute |
| **Lifecycle** | Revoke (RFC 5280 reasons), renew (same key), rotate (new key), hard-delete |
| **CRL** | Build, sign, and verify Certificate Revocation Lists with configurable validity |
| **Inspection** | Structured `CertificateDetails` snapshot from any `x509.Certificate` — fully serialisable |
| **Export** | PKCS#12 (`.p12`/`.pfx`) bundles with full CA chain |
| **Co-signing** | Re-sign third-party certificates under your CA, preserving Subject and extensions |
| **Chain** | Build `[leaf, ca]` fullchain ready for nginx, Apache, or Envoy |
| **Monitoring** | List certs with filters, find expiring-soon, bulk-expire stale records |
| **Storage** | `LocalStorage` (sync) and `AsyncLocalStorage` (async, aiofiles) with UUID-based isolation |
| **Database** | `SyncDBHandler` (SQLAlchemy) and `AsyncDBHandler` (aiosqlite) — SQLite, PostgreSQL, MySQL |
| **API parity** | `CertLifecycleManager` and `AsyncCertLifecycleManager` are feature-identical |
| **Serial numbers** | `SerialWithEncoding` — 160-bit RFC 5280-compliant, type-prefixed, name-encoded |
| **Test coverage** | **100 %** line and branch coverage across all modules |

---

## Requirements

- **Python** 3.11 or higher
- **Core:** `cryptography >= 46`, `sqlalchemy >= 2`, `pydantic >= 2`
- **Async extras:** `aiofiles`, `aiosqlite`
- **PostgreSQL:** `psycopg2-binary` (sync) / `asyncpg` (async)
- **MySQL:** `pymysql` (sync) / `aiomysql` (async)

---

## Architecture

```
CertLifecycleManager / AsyncCertLifecycleManager   ← application entry-point
        │
        ├── CertificateFactory                      ← crypto-only, zero I/O
        │       ├── ICALoader (Protocol)
        │       │       ├── CAFileLoader            ← sync PEM file loader
        │       │       └── AsyncCAFileLoader       ← async PEM file loader
        │       ├── CertLifetime                    ← validity window helpers
        │       ├── CertSerialParser                ← read serials from certs
        │       └── SerialWithEncoding              ← encode / decode serial numbers
        │
        ├── BaseStorage (ABC)
        │       ├── LocalStorage                    ← sync filesystem (UUID-isolated)
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

storage = LocalStorage(base_folder="./pki")
db = SyncDBHandler(db_url="sqlite:///pki.db")
mgr = CertLifecycleManager(storage=storage, db_handler=db)

cert_path, key_path = mgr.create_self_signed_ca(
    CAConfig(common_name="My Root CA", organization="ACME Corp",
             country="UA", key_size=4096, days_valid=3650)
)
```

Attach the factory so the manager can issue certificates:

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
```

### 3. Renew a Certificate (same key)

Keeps the existing public key — only validity window and serial number change.
Use when the key has **not** been compromised.

```python
renewed = mgr.renew_certificate(serial=cert.serial_number, days_valid=365)
```

### 4. Rotate a Certificate (new key)

Atomically revokes the old cert and issues a replacement with a fresh key pair.

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

### 7. Issue an Intermediate CA

```python
sub_ca_cert, sub_ca_key = mgr.issue_intermediate_ca(
    common_name="Issuing CA", key_size=4096, days_valid=1825,
    path_length=0, organization="ACME Corp", country="UA",
    cert_path="intermediate",
)
```

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
mgr.delete_certificate(serial=cert.serial_number)
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
                     key_size=2048, days_valid=365, is_server_cert=True)
    )
    details = await mgr.inspect_certificate(cert)
    p12 = await mgr.export_pkcs12(cert, key, password=b"secret")

asyncio.run(main())
```

---

## Complete Examples

| File | Description |
|---|---|
| `examples/complete_example.py` | Sync API — full lifecycle |
| `examples/acomplete_example.py` | Async API — full lifecycle |

```bash
python examples/complete_example.py
python examples/acomplete_example.py
```

---

## Configuration Models

### `CAConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `common_name` | `str` | `"Internal CA"` | CA Common Name (CN) |
| `organization` | `str` | `"My Company"` | Organization (O) |
| `country` | `str` | `"UA"` | Two-letter ISO 3166-1 alpha-2 code |
| `key_size` | `int` | `2048` | RSA key length in bits |
| `days_valid` | `int` | `3650` | Validity period in days |
| `valid_from` | `datetime \| None` | `None` | Explicit UTC start; `None` = now |

### `ClientConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `common_name` | `str` | — | Certificate CN |
| `serial_type` | `CertType` | `SERVICE` | Certificate category |
| `key_size` | `int` | `2048` | RSA key length |
| `days_valid` | `int` | `3650` | Validity period |
| `email` | `EmailStr \| None` | `None` | `emailAddress` Subject attribute |
| `is_server_cert` | `bool` | `True` | Adds ServerAuth EKU + CN as DNS SAN |
| `is_client_cert` | `bool` | `False` | Adds ClientAuth EKU |
| `san_dns` | `list[str] \| None` | `None` | Extra DNS Subject Alternative Names |
| `san_ip` | `list[str] \| None` | `None` | IP address SANs |
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
storage = LocalStorage(base_folder="./pki")
```

```
./pki/
└── [cert_path/]
    └── <uuid>/
        ├── nginx.pem    ← x509.Certificate
        ├── nginx.key    ← RSA private key
        └── nginx.csr    ← CSR
```

### `AsyncLocalStorage` (async)

Drop-in async replacement — same constructor, same layout, all I/O via `aiofiles`.

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

---

## Serial Number Encoding

`SerialWithEncoding` packs three fields into a 160-bit integer (RFC 5280):

```
┌──────────────┬──────────────────────┬────────────────────┐
│  16-bit type │  80-bit name         │  64-bit random     │
│  prefix      │  (up to 10 chars)    │  (UUID fragment)   │
└──────────────┴──────────────────────┴────────────────────┘
```

```python
from tiny_ca.utils.serial_generator import SerialWithEncoding
from tiny_ca.const import CertType

serial = SerialWithEncoding.generate("nginx", CertType.SERVICE)
cert_type, name = SerialWithEncoding.parse(serial)
# cert_type == CertType.SERVICE, name == "nginx"
```

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

---

## FAQ

**Can I use an existing CA?**
Yes — load it with `CAFileLoader` or `AsyncCAFileLoader`.

**What's the difference between `renew` and `rotate`?**
`renew` keeps the key pair and extends validity. `rotate` generates a new key and revokes the old cert.

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
├── const.py                        # CertType, ALLOWED_CERT_EXTENSIONS
├── exc.py                          # all custom exceptions
├── settings.py                     # DEFAULT_LOGGER
├── ca_factory/
│   ├── factory.py                  # CertificateFactory — all crypto
│   └── utils/
│       ├── file_loader.py          # CAFileLoader + ICALoader Protocol
│       ├── afile_loader.py         # AsyncCAFileLoader
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
│   └── certificate.py              # CAConfig, ClientConfig, CertificateDetails
├── storage/
│   ├── base_storage.py             # BaseStorage ABC
│   ├── const.py                    # CryptoObject type alias
│   ├── local_storage.py            # LocalStorage
│   └── async_local_storage.py      # AsyncLocalStorage
└── utils/
    └── serial_generator.py         # SerialWithEncoding
```

---

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
| aiofiles | Apache 2.0 |
