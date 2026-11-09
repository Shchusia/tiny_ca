# tiny_ca
[![Python](https://img.shields.io/pypi/pyversions/tiny-ca)](https://pypi.org/project/tiny-ca/)
[![PyPI](https://img.shields.io/pypi/v/tiny-ca?color=blue)](https://pypi.org/project/tiny-ca/)

[![Coverage Status](https://coveralls.io/repos/github/Shchusia/tiny_ca/badge.svg?branch=feature/docs)](https://coveralls.io/github/Shchusia/tiny_ca?branch=feature/docs)
[![Docs](https://img.shields.io/badge/Docs-passing-green)](https://shchusia.github.io/tiny_ca/)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)


Легковісна Python-бібліотека з **покриттям тестами 100 %** для управління повним циклом X.509-сертифікатів — від розгортання самопідписаного кореневого CA до видачі, відкликання, ротації, поновлення та співпідписання кінцевих сертифікатів, генерації та верифікації CRL, експорту PKCS#12-бандлів та видачі проміжних CA — з підтримкою синхронного й асинхронного API.

---

## REST API

> Шукаєте готовий HTTP-сервер на основі **tiny-ca**?
> Завітайте до **[tiny-ca-gateway](https://github.com/Shchusia/tiny-ca-gateway)** — фреймворк-незалежного REST API адаптера з 22 ендпоінтами для повного циклу роботи з сертифікатами.

| | |
|---|---|
| **GitHub** | [github.com/Shchusia/tiny-ca-gateway](https://github.com/Shchusia/tiny-ca-gateway) |
| **Інструкція з інтеграції** | [tiny-ca-gateway/blob/master/README.md](https://github.com/Shchusia/tiny-ca-gateway/blob/master/README.md) |
| **Підтримувані фреймворки** | FastAPI · Flask · aiohttp · Django Ninja |

```bash
pip install "tiny-ca-gateway[fastapi]"   # FastAPI + Uvicorn
pip install "tiny-ca-gateway[flask]"     # Flask + Gunicorn
pip install "tiny-ca-gateway[aiohttp]"   # aiohttp
pip install "tiny-ca-gateway[django]"    # Django + Django Ninja
```

```python
# FastAPI — 22 CA-ендпоінти у 5 рядків
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
# → Swagger UI за адресою http://localhost:8000/docs
```

---

## Зміст

- [Можливості](#можливості)
- [Вимоги](#вимоги)
- [Архітектура](#архітектура)
- [Встановлення](#встановлення)
- [Швидкий старт](#швидкий-старт)
- [Розгортання з підвищеними вимогами безпеки](#розгортання-з-підвищеними-вимогами-безпеки)
- [Повні приклади](#повні-приклади)
- [Моделі конфігурації](#моделі-конфігурації)
- [Сховища](#сховища)
- [Адаптери бази даних](#адаптери-бази-даних)
- [Кодування серійних номерів](#кодування-серійних-номерів)
- [Довідник помилок](#довідник-помилок)
- [FAQ](#faq)
- [Міграція з інших CA](#міграція-з-інших-ca)
- [Результати бенчмарків](#результати-бенчмарків)
- [Структура проєкту](#структура-проєкту)
- [Модель безпеки](#модель-безпеки)
- [Безпека](#безпека)
- [Ліцензія](#ліцензія)

---

## Можливості

| Категорія | Можливість |
|---|---|
| **Розгортання CA** | Самопідписаний кореневий CA і проміжний (підлеглий) CA з налаштуванням `path_length` |
| **Видача** | Листові сертифікати з SAN (DNS + IP), EKU (Server/Client Auth), email-атрибутом |
| **Lifecycle** | Відкликання (RFC 5280), поновлення (той самий ключ), ротація (новий ключ), жорстке видалення |
| **CRL** | Побудова, підписання та верифікація списків відкликань з налаштуванням терміну |
| **Інспекція** | Структурований `CertificateDetails` для будь-якого `x509.Certificate` — повністю серіалізовний |
| **Експорт** | PKCS#12 (`.p12`/`.pfx`) із повним ланцюжком CA |
| **Співпідписання** | Перепідписання чужого сертифіката під цим CA зі збереженням Subject і розширень |
| **Ланцюжок** | Побудова `[leaf, ca]` `fullchain.pem` для nginx, Apache або Envoy |
| **Моніторинг** | Список із фільтрами, сертифікати що спливають, масова позначка прострочених |
| **Сховище** | `LocalStorage` (sync) і `AsyncLocalStorage` (async) з UUID-ізоляцією, приватними ключами `0600` і захистом від path traversal |
| **Алгоритми ключів** | ECDSA P-384 (за замовчуванням), P-256, RSA 2048–8192 (за замовчуванням 3072), Ed25519; підписи SHA-384 для P-384 / RSA ≥ 3072 |
| **HSM / зовнішні підписувачі** | Ключ CA в HSM чи на смарт-картці через PKCS#11 (`SignerCALoader`, `Pkcs11Signer`) або будь-який `CASigner` (хмарний KMS); кореневі та підлеглі сертифікати CA для ключів, що не покидають токен |
| **Політики та обмеження імен** | `CertificatePolicies` з посиланням на CPS у кожному сертифікаті; критичне `NameConstraints` (DNS / IP / email) на проміжних CA, перевіряється при видачі та при валідації ланцюжка |
| **Журнал аудиту** | Підписаний append-only JSONL-журнал із хеш-ланцюжком для кожної операції CA, з офлайн-перевіркою |
| **База даних** | `SyncDBHandler` (SQLAlchemy) і `AsyncDBHandler` (aiosqlite) — SQLite, PostgreSQL, MySQL |
| **Паритет API** | `CertLifecycleManager` і `AsyncCertLifecycleManager` мають ідентичний набір методів |
| **Серійні номери** | `SerialWithEncoding` — 160-бітні RFC 5280, з префіксом типу та фрагментом імені |
| **Тестування** | **100 %** покриття рядків і гілок по всіх модулях |

---

## Вимоги

- **Python** 3.11 або вище
- **Основні:** `cryptography >= 46`, `sqlalchemy >= 2`, `pydantic >= 2`
- **Async-extras:** `aiosqlite`
- **PostgreSQL:** `psycopg2-binary` (sync) / `asyncpg` (async)
- **MySQL:** `pymysql` (sync) / `aiomysql` (async)
- **HSM:** `python-pkcs11` (`tiny-ca[hsm]`)

---

## Архітектура

```
CertLifecycleManager / AsyncCertLifecycleManager   ← точка входу
        │
        ├── CertificateFactory                      ← тільки крипто, без I/O
        │       ├── ICALoader (Protocol)
        │       │       ├── CAFileLoader            ← sync PEM-завантажувач
        │       │       └── AsyncCAFileLoader       ← async PEM-завантажувач
        │       ├── ISignerCALoader (Protocol)
        │       │       └── SignerCALoader          ← сертифікат CA + CASigner (HSM / KMS)
        │       ├── CASigner (Protocol)             ← KeySigner, Pkcs11Signer
        │       ├── CertLifetime                    ← утиліти вікна валідності
        │       ├── CertSerialParser                ← читання серійних номерів
        │       └── SerialWithEncoding              ← кодування/декодування серійних номерів
        │
        ├── BaseStorage (ABC)
        │       ├── LocalStorage                    ← sync файлова система (UUID-ізоляція)
        │       └── AsyncLocalStorage               ← async файлова система (робочі потоки)
        │
        ├── BaseDB (ABC)
        │       ├── SyncDBHandler                   ← SQLAlchemy sync
        │       └── AsyncDBHandler                  ← SQLAlchemy async (aiosqlite)
        │
        └── AuditLog                                ← необов'язковий підписаний журнал з хеш-ланцюжком
```

Кожен компонент інжектується при конструюванні — жодних глобальних синглтонів, легко тестується і мокується.

---

## Встановлення

```bash
# Тільки sync (мінімум)
pip install tiny-ca

# З підтримкою async (рекомендовано)
pip install tiny-ca[async]

# PostgreSQL
pip install tiny-ca[postgres]           # sync (psycopg2)
pip install tiny-ca[postgres-async]     # async (asyncpg)

# MySQL
pip install tiny-ca[mysql]              # sync (pymysql)
pip install tiny-ca[mysql-async]        # async (aiomysql)

# HSM / смарт-картка (PKCS#11)
pip install tiny-ca[hsm]

# Все одразу
pip install tiny-ca[all]
```

---

## Швидкий старт

### 1. Розгортання кореневого CA

```python
from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
from tiny_ca.storage.local_storage import LocalStorage
from tiny_ca.db.sync_db_manager import SyncDBHandler
from tiny_ca.models.certificate import CAConfig

storage = LocalStorage(base_folder="./pki")
db = SyncDBHandler(db_url="sqlite:///pki.db")
mgr = CertLifecycleManager(storage=storage, db_handler=db)

cert_path, key_path = mgr.create_self_signed_ca(
    CAConfig(common_name="Мій кореневий CA", organization="ACME Corp",
             country="UA", days_valid=3650)          # ECDSA P-384 за замовчуванням
)
```

Підключіть factory щоб видавати сертифікати:

```python
from tiny_ca.ca_factory.utils.file_loader import CAFileLoader
from tiny_ca.ca_factory.factory import CertificateFactory

loader = CAFileLoader(ca_cert_path=cert_path, ca_key_path=key_path)
mgr.factory = CertificateFactory(loader)
```

Ключі за замовчуванням — ECDSA P-384 (підписи SHA-384).  `CAConfig` /
`ClientConfig` приймають `key_algorithm=KeyAlgorithm.RSA` (3072 біти за
замовчуванням), `EC_P256` або `ED25519`.  Як тримати ключ CA в HSM, див.
[Розгортання з підвищеними вимогами безпеки](#розгортання-з-підвищеними-вимогами-безпеки).

### 2. Видача листового сертифіката

```python
from tiny_ca.models.certificate import ClientConfig
from tiny_ca.const import CertType

cert, key, csr = mgr.issue_certificate(
    ClientConfig(
        common_name="nginx.internal",
        serial_type=CertType.SERVICE,
        days_valid=365,
        is_server_cert=True,
        san_dns=["nginx.internal", "www.nginx.internal"],
        san_ip=["192.168.1.10"],
    ),
    cert_path="services",
)
```

### 3. Поновлення сертифіката (той самий ключ)

Зберігає існуючий публічний ключ — змінюється лише вікно валідності та серійний номер.
Використовуйте коли приватний ключ **не скомпрометований**.

```python
renewed = mgr.renew_certificate(serial=cert.serial_number, days_valid=365)
```

### 4. Ротація сертифіката (новий ключ)

Атомарно відкликає старий сертифікат і видає заміну з новою парою ключів.

```python
new_cert, new_key, new_csr = mgr.rotate_certificate(
    serial=cert.serial_number,
    config=ClientConfig(common_name="nginx.internal",
                        serial_type=CertType.SERVICE, days_valid=365,
                        is_server_cert=True),
)
```

### 5. Відкликання сертифіката

```python
from cryptography import x509
mgr.revoke_certificate(serial=cert.serial_number, reason=x509.ReasonFlags.key_compromise)
```

### 6. Генерація та верифікація CRL

```python
crl = mgr.generate_crl(days_valid=7)   # записується в <base_folder>/crl.pem
mgr.verify_crl(crl)                     # кидає ValidationCertError при помилці
```

### 7. Видача проміжного CA

```python
sub_ca_cert, sub_ca_key = mgr.issue_intermediate_ca(
    common_name="Видавальний CA", key_size=4096, days_valid=1825,
    path_length=0, organization="ACME Corp", country="UA",
    cert_path="intermediate",
)
```

Передайте `name_constraints=NameConstraintsConfig(...)`, щоб обмежити імена,
які може сертифікувати проміжний CA.  Якщо його ключ генерується деінде
(напр. у власному HSM), використовуйте `certify_intermediate_ca(csr, ...)`.

### 8. Експорт PKCS#12

```python
p12_bytes = mgr.export_pkcs12(cert=cert, private_key=key,
                               password=b"надійний-пароль", name="nginx.internal")
with open("nginx.p12", "wb") as f:
    f.write(p12_bytes)
```

### 9. Співпідписання чужого сертифіката

```python
from cryptography import x509
third_party = x509.load_pem_x509_certificate(open("partner.pem", "rb").read())
cosigned = mgr.cosign_certificate(cert=third_party, days_valid=365)
```

### 10. Інспекція сертифіката

```python
details = mgr.inspect_certificate(cert)
print(details.common_name, details.fingerprint_sha256, details.public_key_size)

# fullchain.pem для nginx
from cryptography.hazmat.primitives.serialization import Encoding
chain = mgr.get_cert_chain(cert)
fullchain_pem = b"".join(c.public_bytes(Encoding.PEM) for c in chain)
```

### 11. Моніторинг сертифікатів

```python
records  = mgr.list_certificates(status="valid", key_type="service", limit=50)
expiring = mgr.get_expiring_soon(within_days=30)
updated  = mgr.refresh_expired_statuses()   # запускати по розкладу
mgr.delete_certificate(serial=cert.serial_number)  # відкликаний і не прострочений → CertificateRevokedError (запис лишається в CRL)
```

### 12. Асинхронне використання

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

## Розгортання з підвищеними вимогами безпеки

Можливості для PKI, що працює за формальною політикою безпеки.  Що вони
гарантують, а що ні, див. у розділі [Модель безпеки](#модель-безпеки).

### Ключ CA в HSM

Ключ CA може зберігатися в HSM або на смарт-картці й ніколи не
завантажуватися в процес.  Встановіть extra:
`pip install 'tiny-ca[hsm]'`.

```python
import os
from tiny_ca import CertificateFactory, SignerCALoader

loader = SignerCALoader.from_pkcs11(
    ca_cert="pki/ca.pem",                         # лише сертифікат, без файлу ключа
    module_path="/usr/lib/softhsm/libsofthsm2.so",
    token_label="ca-token",
    pin=os.environ["CA_TOKEN_PIN"],
    key_label="root-ca",                          # або key_id=b"\x01"
)
mgr.factory = CertificateFactory(loader)
# ... видача, поновлення, відкликання, CRL — кожен підпис робить токен
loader.ca_signer.close()                          # завершити сесію PKCS#11
```

Під час запуску `SignerCALoader` перевіряє три речі:
- сертифікат є сертифікатом CA;
- ключ на токені відповідає сертифікату;
- токен підписує випадковий виклик.

Кожен підпис від токена перевіряється сертифікатом CA, перш ніж сертифікат
або CRL покине factory.  Будь-який інший бекенд (хмарний KMS, віддалений
сервіс підпису) підключається через протокол `CASigner`:

```python
from tiny_ca import CASigner, SignerCALoader

class KmsSigner:                                   # реалізує CASigner
    def public_key(self):
        return ca_cert.public_key()

    def sign(self, data: bytes, algorithm) -> bytes:
        # algorithm: hashes.SHA384() / SHA256(), або None для Ed25519.
        # Повертає PKCS#1 v1.5 (RSA), DER ECDSA-Sig-Value (EC) або сирий Ed25519.
        return kms_client.sign(data, algorithm)

loader = SignerCALoader(ca_cert, KmsSigner())
```

**Ключі, згенеровані на токені.**  Створіть пару ключів засобами токена,
наприклад `pkcs11-tool --keypairgen --key-type EC:secp384r1 --label root-ca`.
Потім сертифікуйте її так, щоб ключ ніколи не покидав токен:

```python
from tiny_ca import Pkcs11Signer

# Кореневий CA: публічний ключ береться з токена (або з CSR, створеного ним).
signer = Pkcs11Signer.open(module_path, "ca-token", pin,
                           public_key=token_public_key, key_label="root-ca")
root_cert = CertificateFactory.build_self_signed_ca_with_signer(
    signer, common_name="ACME Root CA", organization="ACME", country="UA")

# Підлеглий CA, ключ якого в іншому HSM: сертифікуємо його CSR.
sub_cert = mgr.certify_intermediate_ca(sub_ca_csr, common_name="ACME Issuing CA")
```

`certify_intermediate_ca` перевіряє підпис CSR як доказ володіння ключем.
Subject бере з власних аргументів, ніколи не з CSR.  Зберігає й реєструє
лише сертифікат.

### Політики сертифікатів і обмеження імен

```python
from tiny_ca import CertificateFactory, NameConstraintsConfig

mgr.factory = CertificateFactory(
    loader,
    certificate_policies=["1.3.6.1.4.1.55555.1.1"],   # OID вашої CP
    cps_uri="https://pki.example.com/cps",
)

sub_cert, sub_key = mgr.issue_intermediate_ca(
    "Issuing CA - example.com",
    name_constraints=NameConstraintsConfig(
        permitted_dns=["example.com"],        # example.com і піддомени
        excluded_dns=["secret.example.com"],
        permitted_ip=["10.0.0.0/8"],
        permitted_email=["example.com"],       # скриньки @example.com
    ),
)
```

- `CertificatePolicies` (з необов'язковим посиланням на CPS) додається до
  кожного сертифіката, який factory видає, поновлює, співпідписує або
  сертифікує.
- `NameConstraints` — критичне розширення проміжного CA.  Воно
  застосовується у двох місцях:
  - `validate_chain` / `verify_certificate` перевіряють кожен сертифікат
    під обмеженим CA;
  - factory, що працює *на* обмеженому CA, відмовляється видавати,
    поновлювати чи співпідписувати сертифікат із забороненим DNS / IP /
    email-ім'ям і кидає `NameConstraintViolation`.
- Wildcard обробляється консервативно: `*.com` відхиляється, якщо
  `evil.com` виключено.
- Обмеження для типів імен, які tiny-ca не вміє оцінити (directoryName,
  URI, otherName, registeredID), спрацьовують як відмова.

### Захищений від підробки журнал аудиту

```python
from tiny_ca import AuditLog, CertLifecycleManager

audit = AuditLog("/var/log/pki/audit.jsonl",
                 signer=audit_key,            # окремий ключ або CASigner (HSM)
                 actor="pki-operator-1")
mgr = CertLifecycleManager(storage=storage, db_handler=db, factory=factory,
                           audit_log=audit)

# ... пізніше, напр. щоденною задачею, з head-хешем, збереженим деінде:
count = AuditLog.verify("/var/log/pki/audit.jsonl",
                        public_key=audit_key.public_key(),
                        expected_head=last_published_head)
```

Кожна операція, що змінює стан, додає один JSON-рядок.  Це створення CA,
видача, ротація, поновлення, співпідписання, видача або сертифікація
проміжного CA, відкликання (включно з невдалими спробами), видалення,
генерація CRL та експорт PKCS#12.  Кожен рядок містить:
- порядковий номер, час UTC, актора й подію;
- серійний номер сертифіката, subject, issuer і відбиток SHA-256;
- хеш попереднього рядка і власний хеш рядка;
- підпис, якщо налаштовано ключ підпису.

`AuditLog.verify` виявляє змінені, вставлені, переставлені й видалені
записи.  Щоб виявити видалення *останніх* записів, регулярно публікуйте
`audit.head` туди, де хост CA не може його переписати (SIEM, тікет, інший
хост), і передавайте як `expected_head`.

### Значення за замовчуванням

| Параметр | За замовчуванням у 1.0 | Як змінити |
|---|---|---|
| Алгоритм ключа | ECDSA P-384 | `key_algorithm=KeyAlgorithm.RSA / EC_P256 / ED25519` |
| Розмір RSA-ключа | 3072 біти (допустимо 2048–8192, попередження нижче 3072) | `key_size=` |
| Дайджест підпису | SHA-384 для P-384 і RSA ≥ 3072, SHA-256 для P-256 / RSA-2048 | визначається ключем CA |
| Строк дії листового сертифіката | 365 днів (допустимо 1–36500) | `days_valid=` |
| Строк дії CA | 3650 днів; видані сертифікати не переживають CA | `days_valid=` |

---

## Повні приклади

| Файл | Опис |
|---|---|
| `examples/complete_example.py` | Sync API — повний lifecycle |
| `examples/acomplete_example.py` | Async API — повний lifecycle |
| `examples/high_assurance_example.py` | Підписувач у стилі HSM, політики сертифікатів, підлеглий CA з обмеженнями імен, підписаний журнал аудиту |

```bash
python examples/complete_example.py
python examples/acomplete_example.py
python examples/high_assurance_example.py
```

---

## Моделі конфігурації

### `CAConfig`

| Поле | Тип | За замовчуванням | Опис |
|---|---|---|---|
| `common_name` | `str` | `"Internal CA"` | CN кореневого CA |
| `organization` | `str` | `"My Company"` | Організація (O) |
| `country` | `str` | `"UA"` | Двобуквений код країни ISO 3166-1 |
| `key_size` | `int` | `3072` | Довжина RSA-ключа в бітах (2048–8192; ігнорується для EC / Ed25519) |
| `key_algorithm` | `KeyAlgorithm` | `EC_P384` | `EC_P384`, `EC_P256`, `RSA` або `ED25519` |
| `days_valid` | `int` | `3650` | Термін дії в днях (1–36500) |
| `valid_from` | `datetime \| None` | `None` | Явний початок (UTC); `None` = зараз |

### `ClientConfig`

| Поле | Тип | За замовчуванням | Опис |
|---|---|---|---|
| `common_name` | `str` | — | CN сертифіката |
| `serial_type` | `CertType` | `SERVICE` | Категорія сертифіката |
| `key_size` | `int` | `3072` | Довжина RSA-ключа (2048–8192; ігнорується для EC / Ed25519) |
| `key_algorithm` | `KeyAlgorithm` | `EC_P384` | `EC_P384`, `EC_P256`, `RSA` або `ED25519` |
| `days_valid` | `int` | `365` | Термін дії (1–36500; обрізається до строку дії CA) |
| `email` | `EmailStr \| None` | `None` | Атрибут `emailAddress` у Subject |
| `is_server_cert` | `bool` | `True` | Додає ServerAuth EKU + CN як DNS SAN |
| `is_client_cert` | `bool` | `False` | Додає ClientAuth EKU |
| `san_dns` | `list[str] \| None` | `None` | Додаткові DNS SAN |
| `san_ip` | `list[str] \| None` | `None` | IP-адреси SAN |
| `name` | `str \| None` | `None` | Перевизначення базового імені файлу |

### Перелік `CertType`

| Значення | Рядок | Опис |
|---|---|---|
| `CertType.CA` | `"CA"` | Кореневий або проміжний CA |
| `CertType.USER` | `"USR"` | Персональний сертифікат користувача |
| `CertType.SERVICE` | `"SVC"` | Сертифікат сервісу / сервера |
| `CertType.DEVICE` | `"DEV"` | Сертифікат пристрою (IoT тощо) |
| `CertType.INTERNAL` | `"INT"` | Внутрішній інфраструктурний сертифікат |

---

## Сховища

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
        ├── nginx.key    ← RSA приватний ключ
        └── nginx.csr    ← CSR
```

### `AsyncLocalStorage` (async)

Пряма async-заміна — однаковий конструктор, однакова структура і ті самі гарантії безпеки; блокуючий I/O виконується в робочих потоках.

> **З версії 0.3.0:** приватні ключі записуються з правами `0600` (без шифрування, якщо не передано
> `base_encryption_algorithm=BestAvailableEncryption(...)`); `file_name` / `cert_path` / `uuid_str`
> перевіряються на вихід за межі `base_folder`; помилки БД під час читання піднімають `DBOperationError`
> (fail-closed) — порожній CRL ніколи не публікується. Деталі — у `CHANGELOG.md`.

---

## Адаптери бази даних

```python
# Sync
db = SyncDBHandler(db_url="sqlite:///pki.db")
db = SyncDBHandler(db_url="postgresql+psycopg2://user:pass@host/pki")

# Async
db = AsyncDBHandler(db_url="sqlite+aiosqlite:///pki.db")
db = AsyncDBHandler(db_url="postgresql+asyncpg://user:pass@host/pki")
await db._db.init_db()
```

### Контракт `BaseDB`

| Метод | Опис |
|---|---|
| `get_by_serial(serial)` | Отримати запис за серійним номером |
| `get_by_name(cn)` | Отримати активний VALID-запис за CN |
| `register_cert_in_db(cert, uuid, key_type)` | Зберегти новий сертифікат |
| `revoke_certificate(serial, reason)` | Позначити як відкликаний (RFC 5280) |
| `get_revoked_certificates()` | Генератор рядків для побудови CRL |
| `list_all(status, key_type, limit, offset)` | Пагінований список із фільтрами |
| `get_expiring(within_days)` | VALID-сертифікати що спливають за N днів |
| `delete_by_uuid(uuid)` | Жорстке видалення запису |
| `update_status_expired()` | Масово позначити прострочені VALID-записи як EXPIRED |

---

## Кодування серійних номерів

`SerialWithEncoding` пакує три поля в один 160-бітний integer (RFC 5280):

```
┌──────────────────┬──────────────────────┬────────────────────┐
│  16-бітний тип   │  80-бітне ім'я       │  64-бітний random  │
│  (префікс)       │  (до 10 символів)    │  (фрагмент UUID)   │
└──────────────────┴──────────────────────┴────────────────────┘
```

```python
from tiny_ca.utils.serial_generator import SerialWithEncoding
from tiny_ca.const import CertType

serial = SerialWithEncoding.generate("nginx", CertType.SERVICE)
cert_type, name = SerialWithEncoding.parse(serial)
# cert_type == CertType.SERVICE, name == "nginx"
```

---

## Довідник помилок

| Виняток | Коли виникає | Вирішення |
|---|---|---|
| `DBNotInitedError` | `db_handler is None` | Передайте `db_handler` в менеджер |
| `NotUniqueCertOwner` | Конфлікт CN, `is_overwrite=False` | Використайте `is_overwrite=True` |
| `CertNotFound` | `renew`/`rotate` для неіснуючого серійного | Перевірте серійний номер |
| `ValidationCertError` | Невірний емітент, прострочений, невірний підпис | Перевірте сертифікат і CA |
| `InvalidRangeTimeCertificate` | `not_after` вже в минулому | Виправте `valid_from` або `days_valid` |
| `FileAlreadyExists` | Файл існує, `is_overwrite=False` | Використайте `is_overwrite=True` |
| `NotExistCertFile` | Шлях до PEM-файлу CA не існує | Перевірте шлях до файлу |
| `IsNotFile` | Шлях до PEM — директорія | Вкажіть файл, а не директорію |
| `WrongType` | Непідтримуване розширення | Використайте `.pem`, `.key`, `.csr` |
| `ErrorLoadCert` | Десеріалізація PEM не вдалась | Перевірте формат та цілісність файлу |
| `DBOperationError` | Реєстр не вдалося прочитати / записати | Перевірте БД; нічого не було довірено чи опубліковано |
| `CertRevocationError` | Ротація/поновлення не змогли відкликати старий сертифікат | Повторіть; заміну відкочено |
| `InvalidPathError` | Шлях сховища виходить за `base_folder` | Використовуйте прості імена / відносні підшляхи |
| `CertificateRevokedError` | Поновлення / співпідписання відкликаного, видалення відкликаного й ще чинного | Видайте новий сертифікат; зберігайте відкликані записи до їх закінчення |
| `NameConstraintViolation` | Ім'я поза `NameConstraints` емітента | Використайте дозволене ім'я або інший видавальний CA |
| `SignerError` | Зовнішній підписувач (HSM / KMS) збій або повернув невірний підпис | Перевірте токен, PIN, мітку ключа та відповідність ключа сертифікату CA |
| `AuditLogError` | Запис аудиту не вдалося записати або перевірка не пройшла | Розглядайте як інцидент безпеки: операція відбулася, але не записана |

---

## FAQ

**Чи можна використовувати існуючий CA?**
Так — завантажте його через `CAFileLoader` або `AsyncCAFileLoader`.

**В чому різниця між `renew` і `rotate`?**
`renew` зберігає пару ключів і продовжує валідність. `rotate` генерує новий ключ і відкликає старий сертифікат.

**Чому після оновлення до 1.0 нові ключі EC, а не RSA?**
1.0 за замовчуванням використовує ECDSA P-384 із SHA-384.  Передайте
`key_algorithm=KeyAlgorithm.RSA` (і `key_size=`), де потрібен RSA.  Наявні CA
зберігають свій алгоритм; дайджест підпису тепер залежить від розміру ключа
(SHA-384 для RSA ≥ 3072).  Див. «Breaking changes» 1.0.0 у
[CHANGELOG.md](CHANGELOG.md).

**Як запланувати регенерацію CRL?**
```python
scheduler.add_job(mgr.generate_crl, "cron", day_of_week="mon", hour=0)
```

**Чи можна реалізувати власне сховище (S3, Redis)?**
Так — успадкуйте `BaseStorage` і реалізуйте `save_certificate` та `delete_certificate_folder`.

**Як захистити приватний ключ CA паролем?**
```python
loader = CAFileLoader(ca_cert_path="ca.pem", ca_key_path="ca.key",
                      ca_key_password=b"пароль")
```

---

## Міграція з інших CA

### З OpenSSL

```bash
openssl x509 -in ca.crt -out ca.pem -outform PEM
openssl rsa  -in ca.key -out ca-key.pem -outform PEM
```
```python
loader = CAFileLoader(ca_cert_path="ca.pem", ca_key_path="ca-key.pem")
mgr.factory = CertificateFactory(loader)
```

### З Easy-RSA / CFSSL

Обидва інструменти виводять стандартні PEM-файли — виконайте кроки міграції з OpenSSL.

---

## Результати бенчмарків

*Linux 6.17, Python 3.11.15, 32-ядерний CPU, NVMe SSD. 5 ітерацій кожна.*

| Операція | Sync | Async |
|---|---|---|
| Створення CA (2048-біт) | 0.037 с | 0.067 с |
| Створення CA (4096-біт) | 0.317 с | 0.411 с |
| Видача листового сертифіката (2048-біт) | 0.055 с | 0.052 с |
| Видача листового сертифіката (4096-біт) | 0.476 с | 0.712 с |
| Генерація CRL | 0.001 с | 0.002 с |
| Верифікація сертифіката | 0.0003 с | 0.0008 с |
| Експорт PKCS#12 | 0.0005 с | 0.0006 с |

Час генерації RSA-ключа домінує у часі видачі. Для навантаження >1 000 сертифікатів/год рекомендується PostgreSQL, async API та connection pooling.

---

## Структура проєкту

```
tiny_ca/
├── const.py                        # CertType, KeyAlgorithm, безпечні значення / межі
├── signing.py                      # CASigner, KeySigner, Pkcs11Signer, sign_builder
├── audit.py                        # AuditLog — підписаний журнал з хеш-ланцюжком
├── exc.py                          # всі власні винятки
├── settings.py                     # DEFAULT_LOGGER
├── ca_factory/
│   ├── factory.py                  # CertificateFactory — вся крипто-генерація
│   └── utils/
│       ├── file_loader.py          # CAFileLoader + ICALoader Protocol
│       ├── afile_loader.py         # AsyncCAFileLoader
│       ├── signer_loader.py        # SignerCALoader + ISignerCALoader Protocol
│       ├── name_constraints.py     # побудова / перевірка NameConstraints
│       ├── life_time.py            # CertLifetime
│       └── serial.py               # CertSerialParser
├── db/
│   ├── base_db.py                  # BaseDB — 9 абстрактних методів
│   ├── models.py                   # CertificateRecord ORM-модель
│   ├── const.py                    # RevokeStatus, CertificateStatus
│   ├── sync_db_manager.py          # SyncDBHandler
│   └── async_db_manager.py         # AsyncDBHandler
├── managers/
│   ├── sync_lifecycle_manager.py   # CertLifecycleManager (20+ операцій)
│   └── async_lifecycle_manager.py  # AsyncCertLifecycleManager
├── models/
│   └── certificate.py              # CAConfig, ClientConfig, NameConstraintsConfig, CertificateDetails
├── storage/
│   ├── base_storage.py             # BaseStorage ABC
│   ├── const.py                    # Псевдонім типу CryptoObject
│   ├── local_storage.py            # LocalStorage
│   └── async_local_storage.py      # AsyncLocalStorage
└── utils/
    └── serial_generator.py         # SerialWithEncoding
```

---

## Модель безпеки

tiny-ca дає будівельні блоки PKI з підвищеними вимогами безпеки:
- ключ CA в HSM;
- надійні значення за замовчуванням;
- політики сертифікатів і обмеження імен;
- fail-closed перевірки відкликання;
- підписаний журнал аудиту.

Сама бібліотека **не** сертифікована за жодною національною схемою, схемою
NATO чи Common Criteria.  Вона спирається на пакет `cryptography`
(OpenSSL), який не є валідованим модулем FIPS 140-3, якщо його не зібрано
з таким модулем.  Акредитація охоплює й те, що лежить поза бібліотекою:
операційне середовище, розділення ролей і подвійний контроль операцій CA,
ключові церемонії, фізичну безпеку та опубліковані CP/CPS.  Плануйте їх
окремо.

Відомі обмеження:
- OCSP-респондера немає.  Публікуйте CRL (`generate_crl`) і вказуйте їх
  через `crl_distribution_points`.
- Обмеження імен охоплюють DNS, IP та email.  Інші типи спрацьовують як
  відмова.
- Журнал аудиту пишеться після завершення операції.  Його хвіст захищений
  лише публікацією head-хешу деінде.  На Windows немає міжпроцесного
  блокування.
- Без HSM ключ CA — це файл.  Тримайте його зашифрованим
  (`base_encryption_algorithm`) на офлайн-хості або хості під суворим
  контролем.

## Безпека

**Не відкривайте публічні issues** для повідомлень про вразливості безпеки. Напишіть мейнтейнеру на email (див. GitHub-профіль). Підтвердження протягом 48 годин; публічний advisory — лише після виходу виправлення.

---

## Ліцензія

[MIT](LICENSE) © 2025 Denis Shchutskyi

| Залежність | Ліцензія |
|---|---|
| cryptography | BSD 3-Clause |
| SQLAlchemy | MIT |
| Pydantic | MIT |
| aiosqlite | MIT |
| python-pkcs11 (необов'язково, `hsm`) | MIT |
