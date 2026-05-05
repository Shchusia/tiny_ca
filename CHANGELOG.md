# Changelog

All notable changes to **tiny-ca** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2025-05-05

### Added

**`CertificateFactory`**
- `export_pkcs12(cert, key, password, name)` — pack a certificate and its private key into a PKCS#12 (`.p12` / `.pfx`) bundle; the issuing CA is automatically included in the chain.
- `get_cert_chain(cert)` — return `[leaf, ca_cert]` ordered for `ssl_certificate` / `fullchain.pem` use in nginx, Apache, and Envoy.
- `renew_certificate(cert, days_valid, valid_from)` — re-issue a certificate with the **same public key** and a fresh validity window and serial number. Distinct from rotation: the key pair is preserved.
- `issue_intermediate_ca(common_name, ...)` — issue a subordinate CA certificate signed by this CA with configurable `path_length`, `key_size`, `organization`, and `country`.
- `verify_crl(crl)` — verify a `CertificateRevocationList` issuer match, signature, and `nextUpdate` expiry; raises `ValidationCertError` on failure.
- `cosign_certificate(cert, days_valid, valid_from)` — re-sign a third-party certificate under this CA's key while preserving the original Subject, public key, and all v3 extensions.
- `inspect_certificate(cert)` — return a frozen `CertificateDetails` Pydantic model with serial, CN, SANs, key usage, EKU, fingerprint, SKI, and public key size; no `cryptography` objects leak out.

**`BaseDB` / `SyncDBHandler` / `AsyncDBHandler`**
- `list_all(status, key_type, limit, offset)` — paginated certificate listing with optional filters.
- `get_expiring(within_days)` — return VALID certificates whose `not_valid_after` falls within the look-ahead window, ordered soonest-first.
- `delete_by_uuid(uuid)` — hard-delete a certificate record by its storage UUID.
- `update_status_expired()` — bulk-update all VALID records whose `not_valid_after` has passed to `EXPIRED`; designed for periodic background jobs.

**`CertLifecycleManager` / `AsyncCertLifecycleManager`**
- `export_pkcs12`, `get_cert_chain`, `renew_certificate`, `issue_intermediate_ca`, `verify_crl`, `cosign_certificate`, `inspect_certificate` — thin façade methods delegating to `CertificateFactory`; async variants run crypto in a thread pool via `asyncio.to_thread`.
- `list_certificates(status, key_type, limit, offset)` — delegates to `BaseDB.list_all`.
- `get_expiring_soon(within_days)` — delegates to `BaseDB.get_expiring`.
- `delete_certificate(serial, cert_path)` — removes the DB record **and** the artefact folder from storage atomically (best-effort on storage).
- `refresh_expired_statuses()` — delegates to `BaseDB.update_status_expired`; intended for cron / APScheduler use.

**`CertLifetime`**
- `normalize_dt(dt)` — centralised helper that makes a naive `datetime` timezone-aware by assuming UTC. Previously this three-line guard was inlined in both lifecycle managers.

**`pyproject.toml`**
- Added `[project.optional-dependencies]`: `async`, `postgres`, `postgres-async`, `mysql`, `mysql-async`, `all`.
- Added `keywords` and additional PyPI classifiers (`Topic :: Security :: Cryptography`, `Typing :: Typed`).
- Added `"Bug Tracker"` and `Changelog` URLs.
- Moved `aiofiles` / `aiosqlite` from core `dependencies` to the `[async]` extra — sync-only users no longer pull async packages.
- Added `aiofiles` and `aiosqlite` to the `tests` dependency group so async tests run in a clean environment.

### Changed

- `ClientConfig.serial_type` default changed from `CertType.CA` to `CertType.SERVICE` — a leaf certificate should never default to a CA-category serial prefix.
- `factory.py` imports of `sqlalchemy.Row` and `CertificateRecord` moved under `TYPE_CHECKING` — the factory module now has **zero** SQLAlchemy runtime dependency; callers that use only the sync path pay no import cost.
- Deferred `from cryptography import x509 as _x509` inside `renew_certificate` removed; parameter renamed `cert_obj` to avoid the name collision with the top-level module import.
- Both lifecycle managers now call `CertLifetime.normalize_dt` instead of inlining `if dt.tzinfo is None` — single source of truth.
- `models/certtificate.py` renamed to `models/certificate.py` (removed accidental double-`t`); all internal imports updated.
- `managers/__init__.py` now exports `AsyncCertLifecycleManager` alongside `CertLifecycleManager`.

### Fixed

- `AsyncCertLifecycleManager.generate_crl` called non-existent `self.factory.abuild_crl()` — replaced with `asyncio.to_thread(self._factory.build_crl, ...)`.
- `AsyncCertLifecycleManager.generate_crl` consumed the async generator `get_revoked_certificates()` directly, causing `TypeError: 'async_generator' object is not iterable` when passed to the thread-bound `build_crl`. Generator is now drained with `[row async for row in ...]` before the thread call.
- `AsyncCertLifecycleManager.issue_certificate` returned `(path_to_cert, path_to_key, path_to_csr)` instead of `(certificate, private_key, csr)`, causing `AttributeError: 'PosixPath' object has no attribute 'serial_number'` in all downstream callers.
- `pyproject.toml` had `dependencies` listed under `[project.urls]` instead of `[project]`, causing `configuration error: project.urls.dependencies must be string` during `uv build`.
- `pyproject.toml` `[tool.mypy]` block contained contradictory options (`no_strict_optional = true` vs `strict_optional = true`; options already implied by `strict = true` were duplicated and in some cases overridden with conflicting values).

### Tests

- Added `tests/conftest.py` with session-scoped `ca_key`, `ca_cert`, `ca_loader`, and `factory` fixtures — the 2048-bit RSA key is generated once per test session instead of once per file.
- `test_sync_db_manager.py` and `test_sync_db_manager_missing.py` merged into a single file; duplicate `revoke_certificate` edge-case tests removed.
- `test_factory_missing_coverage.py` merged into `test_factory.py`; redundant `TestInspectCertificateEdgeCases`, `TestCoSignCertificate`, and `TestSerializeKeyAndCertificatesEdgeCases` classes removed (superseded by the richer classes merged in from the missing-coverage file).
- Removed 33 duplicate tests from `TestMissingCoverage`, `TestAsyncCertLifecycleManagerEdgeCases`, `TestFinalCoverageAsync`, `TestRequireMethodsCoverage`, `TestPersistCertToDB`, `TestAsyncCreateSelfSignedCAWithOverwrite`, `TestAsyncIssueCertificateWithOverwrite`, and `TestAsyncRevokeCertificateLogging` — all coverage they provided is retained by existing test classes.
- Added `TestNormalizeDt` in `test_life_time.py` covering the new `CertLifetime.normalize_dt` method.
- Test coverage remains **100 %** line and branch across all modules.

---

## [0.1.2] — 2025-04-10

### Fixed

- Corrected package discovery configuration in `pyproject.toml` to ensure all `tiny_ca` sub-packages are included in the distribution.
- Fixed edge case in `SyncDBHandler.get_by_name` where a `bytes`-typed Common Name attribute was not decoded before the database query.

---

## [0.1.1] — 2025-03-20

### Fixed

- `CAFileLoader._validate_file` now raises `IsNotFile` when the path points to a directory instead of silently failing.
- `CertLifetime.compute` correctly raises `InvalidRangeTimeCertificate` when `valid_from` is in the past and `days_valid` produces an already-expired window.

---

## [0.1.0] — 2025-03-01

### Added

Initial public release.

- `CertificateFactory` — pure-crypto class for building self-signed CAs, issuing leaf certificates, generating CRLs, and validating certificate chains.
- `CAFileLoader` / `AsyncCAFileLoader` — load CA certificate and private key from PEM files; support encrypted keys and str / Path inputs.
- `ICALoader` — `@runtime_checkable` Protocol; any object satisfying the three-property contract is accepted by `CertificateFactory`.
- `CertLifetime` — static helpers for computing and inspecting X.509 validity windows; sync and async variants.
- `CertSerialParser` — read raw and decoded (type + name) serial numbers from `x509.Certificate` objects.
- `SerialWithEncoding` — encode a `CertType` prefix, a name fragment, and a UUID random fragment into a single 160-bit RFC 5280-compliant serial number; parse it back.
- `LocalStorage` / `AsyncLocalStorage` — filesystem storage backends with UUID-based directory isolation and pluggable encoding / format options.
- `SyncDBHandler` / `AsyncDBHandler` — SQLAlchemy-backed certificate registry implementing `BaseDB`; supports SQLite, PostgreSQL, and MySQL.
- `CertLifecycleManager` / `AsyncCertLifecycleManager` — application-level façade orchestrating issuance, revocation, rotation, CRL generation, and certificate verification.
- `CAConfig` / `ClientConfig` / `CertificateInfo` — Pydantic v2 configuration and metadata models.
- Custom exception hierarchy: `DBNotInitedError`, `NotUniqueCertOwner`, `CertNotFound`, `ValidationCertError`, `InvalidRangeTimeCertificate`, `FileAlreadyExists`, `NotExistCertFile`, `IsNotFile`, `WrongType`, `ErrorLoadCert`.

[0.2.0]: https://github.com/Shchusia/tiny_ca/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/Shchusia/tiny_ca/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Shchusia/tiny_ca/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Shchusia/tiny_ca/releases/tag/v0.1.0
