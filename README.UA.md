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
| **Сховище** | `LocalStorage` (sync) і `AsyncLocalStorage` (async, aiofiles) з UUID-ізоляцією |
| **База даних** | `SyncDBHandler` (SQLAlchemy) і `AsyncDBHandler` (aiosqlite) — SQLite, PostgreSQL, MySQL |
| **Паритет API** | `CertLifecycleManager` і `AsyncCertLifecycleManager` мають ідентичний набір методів |
| **Серійні номери** | `SerialWithEncoding` — 160-бітні RFC 5280, з префіксом типу та фрагментом імені |
| **Тестування** | **100 %** покриття рядків і гілок по всіх модулях |

---

## Вимоги

- **Python** 3.11 або вище
- **Основні:** `cryptography >= 46`, `sqlalchemy >= 2`, `pydantic >= 2`
- **Async-extras:** `aiofiles`, `aiosqlite`
- **PostgreSQL:** `psycopg2-binary` (sync) / `asyncpg` (async)
- **MySQL:** `pymysql` (sync) / `aiomysql` (async)

---

## Архітектура

```
CertLifecycleManager / AsyncCertLifecycleManager   ← точка входу
        │
        ├── CertificateFactory                      ← тільки крипто, без I/O
        │       ├── ICALoader (Protocol)
        │       │       ├── CAFileLoader            ← sync PEM-завантажувач
        │       │       └── AsyncCAFileLoader       ← async PEM-завантажувач
        │       ├── CertLifetime                    ← утиліти вікна валідності
        │       ├── CertSerialParser                ← читання серійних номерів
        │       └── SerialWithEncoding              ← кодування/декодування серійних номерів
        │
        ├── BaseStorage (ABC)
        │       ├── LocalStorage                    ← sync файлова система (UUID-ізоляція)
        │       └── AsyncLocalStorage               ← async файлова система (aiofiles)
        │
        └── BaseDB (ABC)
                ├── SyncDBHandler                   ← SQLAlchemy sync
                └── AsyncDBHandler                  ← SQLAlchemy async (aiosqlite)
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
             country="UA", key_size=4096, days_valid=3650)
)
```

Підключіть factory щоб видавати сертифікати:

```python
from tiny_ca.ca_factory.utils.file_loader import CAFileLoader
from tiny_ca.ca_factory.factory import CertificateFactory

loader = CAFileLoader(ca_cert_path=cert_path, ca_key_path=key_path)
mgr.factory = CertificateFactory(loader)
```

### 2. Видача листового сертифіката

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
mgr.delete_certificate(serial=cert.serial_number)
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

---

## Повні приклади

| Файл | Опис |
|---|---|
| `examples/complete_example.py` | Sync API — повний lifecycle |
| `examples/acomplete_example.py` | Async API — повний lifecycle |

```bash
python examples/complete_example.py
python examples/acomplete_example.py
```

---

## Моделі конфігурації

### `CAConfig`

| Поле | Тип | За замовчуванням | Опис |
|---|---|---|---|
| `common_name` | `str` | `"Internal CA"` | CN кореневого CA |
| `organization` | `str` | `"My Company"` | Організація (O) |
| `country` | `str` | `"UA"` | Двобуквений код країни ISO 3166-1 |
| `key_size` | `int` | `2048` | Довжина RSA-ключа в бітах |
| `days_valid` | `int` | `3650` | Термін дії в днях |
| `valid_from` | `datetime \| None` | `None` | Явний початок (UTC); `None` = зараз |

### `ClientConfig`

| Поле | Тип | За замовчуванням | Опис |
|---|---|---|---|
| `common_name` | `str` | — | CN сертифіката |
| `serial_type` | `CertType` | `SERVICE` | Категорія сертифіката |
| `key_size` | `int` | `2048` | Довжина RSA-ключа |
| `days_valid` | `int` | `3650` | Термін дії |
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

Пряма async-заміна — однаковий конструктор, однакова структура, весь I/O через `aiofiles`.

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

---

## FAQ

**Чи можна використовувати існуючий CA?**
Так — завантажте його через `CAFileLoader` або `AsyncCAFileLoader`.

**В чому різниця між `renew` і `rotate`?**
`renew` зберігає пару ключів і продовжує валідність. `rotate` генерує новий ключ і відкликає старий сертифікат.

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
├── const.py                        # CertType, ALLOWED_CERT_EXTENSIONS
├── exc.py                          # всі власні винятки
├── settings.py                     # DEFAULT_LOGGER
├── ca_factory/
│   ├── factory.py                  # CertificateFactory — вся крипто-генерація
│   └── utils/
│       ├── file_loader.py          # CAFileLoader + ICALoader Protocol
│       ├── afile_loader.py         # AsyncCAFileLoader
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
│   └── certificate.py              # CAConfig, ClientConfig, CertificateDetails
├── storage/
│   ├── base_storage.py             # BaseStorage ABC
│   ├── const.py                    # Псевдонім типу CryptoObject
│   ├── local_storage.py            # LocalStorage
│   └── async_local_storage.py      # AsyncLocalStorage
└── utils/
    └── serial_generator.py         # SerialWithEncoding
```

---

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
| aiofiles | Apache 2.0 |
