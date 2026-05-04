# tiny_ca

[![Coverage Status](https://img.shields.io/badge/%20Python%20Versions-%3E%3D3.11-informational)](https://github.com/Shchusia/tiny_ca)
[![Coverage Status](https://coveralls.io/repos/github/Shchusia/tiny_ca/badge.svg?branch=feature/docs)](https://coveralls.io/github/Shchusia/tiny_ca?branch=feature/docs)

[![Coverage Status](https://img.shields.io/badge/Version-0.1.2-informational)](https://pypi.org/project/tiny_ca/)
[![Coverage Status](https://img.shields.io/badge/Docs-passed-green)](https://shchusia.github.io/tiny_ca/)

Легка Python-бібліотека для керування повним циклом X.509-сертифікатів — від bootstrap самопідписаного кореневого CA до видачі, відкликання та ротації сертифікатів кінцевих сутностей, генерації CRL та збереження всіх артефактів у локальному сховищі з підтримкою реляційної бази даних.

---

## Зміст

- [Можливості](#можливості)
- [Архітектура](#архітектура)
- [Встановлення](#встановлення)
- [Швидкий старт](#швидкий-старт)
  - [1. Bootstrap самопідписаного кореневого CA](#1-bootstrap-самопідписаного-кореневого-ca)
  - [2. Видача сертифіката кінцевої сутності](#2-видача-сертифіката-кінцевої-сутності)
  - [3. Відкликання сертифіката](#3-відкликання-сертифіката)
  - [4. Генерація CRL](#4-генерація-crl)
  - [5. Верифікація сертифіката](#5-верифікація-сертифіката)
  - [6. Ротація сертифіката](#6-ротація-сертифіката)
  - [7. Асинхронне використання](#7-асинхронне-використання)
- [Моделі конфігурації](#моделі-конфігурації)
- [Сховища](#сховища)
- [Адаптери бази даних](#адаптери-бази-даних)
- [Кодування серійного номера](#кодування-серійного-номера)
- [Довідник помилок](#довідник-помилок)
- [Запуск тестів](#запуск-тестів)
- [Структура проекту](#структура-проекту)

---

## Можливості

- **Bootstrap самопідписаного CA** — генерація кореневого сертифіката та ключа одним викликом.
- **Видача сертифікатів** — серверні, клієнтські, пристроїв, користувачів та сервісів із підтримкою SAN (DNS + IP).
- **Відкликання** — позначення сертифікатів як відкликаних у базі даних з кодами причин RFC 5280.
- **Генерація CRL** — побудова та підписання списку відкликання сертифікатів з поточних записів бази даних.
- **Верифікація** — перевірка видавця, вікна дійсності, підпису та статусу відкликання.
- **Ротація** — атомарне відкликання старого сертифіката та видача нового.
- **Підключаємі сховища** — `LocalStorage` та `AsyncLocalStorage` записують PEM/key/CSR/CRL у настроювану файлову систему.
- **Підключаємі БД** — `SyncDBHandler` (SQLAlchemy sync) та `AsyncDBHandler` (SQLAlchemy async/aiosqlite).
- **Синхронний та асинхронний API** — `CertLifecycleManager` і `AsyncCertLifecycleManager` з однаковим набором функцій.
- **Розумні серійні номери** — `SerialWithEncoding` упаковує префікс `CertType`, фрагмент імені та UUID-випадковість в один 160-бітний цілочисельний номер; повністю відповідає RFC 5280.

---

## Архітектура

```
CertLifecycleManager / AsyncCertLifecycleManager
        │
        ├── CertificateFactory          ← лише криптографічні операції
        │       ├── CAFileLoader / AsyncCAFileLoader   ← завантаження CA з PEM-файлів
        │       └── CertLifetime / CertSerialParser    ← допоміжні класи
        │
        ├── BaseStorage
        │       ├── LocalStorage        ← синхронний файловий бекенд
        │       └── AsyncLocalStorage   ← асинхронний файловий бекенд
        │
        └── BaseDB
                ├── SyncDBHandler       ← SQLAlchemy sync
                └── AsyncDBHandler      ← SQLAlchemy async (aiosqlite)
```

Кожен компонент передається через dependency injection — жодного глобального стану, легко тестувати.

---

## Встановлення

```bash
pip install tiny_ca
# підтримка async (aiosqlite + aiofiles)
pip install tiny_ca[async]
```

Залежності: `cryptography`, `sqlalchemy`, `pydantic`.
Опціональні: `aiosqlite`, `aiofiles` (async-бекенди).

---

## Швидкий старт

### 1. Bootstrap самопідписаного кореневого CA

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
print(f"Сертифікат CA: {cert_path}")
print(f"Приватний ключ CA: {key_path}")
```

### 2. Видача сертифіката кінцевої сутності

Після bootstrap потрібно завантажити CA та прив'язати `CertificateFactory`:

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
print(f"Видано: {cert.serial_number}")
```

### 3. Відкликання сертифіката

```python
from cryptography import x509

success = mgr.revoke_certificate(
    serial=cert.serial_number,
    reason=x509.ReasonFlags.key_compromise,
)
print("Відкликано:", success)
```

### 4. Генерація CRL

```python
crl = mgr.generate_crl(days_valid=7)
# Автоматично записується у <base_folder>/crl.pem
```

### 5. Верифікація сертифіката

```python
from tiny_ca.exc import ValidationCertError

try:
    mgr.verify_certificate(cert)
    print("Сертифікат дійсний")
except ValidationCertError as e:
    print(f"Перевірка не пройдена: {e}")
```

### 6. Ротація сертифіката

```python
new_cert, new_key, new_csr = mgr.rotate_certificate(
    serial=cert.serial_number,
    config=svc_config,
)
print(f"Ротовано до серійного: {new_cert.serial_number}")
```

### 7. Асинхронне використання

Всі операції доступні як `async`/`await` через `AsyncCertLifecycleManager`:

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

    # Прив'язати factory
    from tiny_ca.ca_factory.utils.afile_loader import AsyncCAFileLoader
    from tiny_ca.ca_factory.factory import CertificateFactory

    loader = await AsyncCAFileLoader.create(
        cert_path.parent / "ca.pem",
        cert_path.parent / "ca.key",
    )
    mgr.factory = CertificateFactory(loader)

    # Видати сертифікат
    cert, key, csr = await mgr.issue_certificate(
        ClientConfig(common_name="modules.internal", serial_type=CertType.SERVICE,
                     key_size=2048, days_valid=365, is_server_cert=True)
    )
    print("Видано:", cert.serial_number)

asyncio.run(main())
```

---

## Моделі конфігурації

Обидві моделі є Pydantic `BaseModel` — всі поля валідуються при створенні.

### `CAConfig`

| Поле | Тип | Замовчування | Опис |
|---|---|---|---|
| `common_name` | `str` | — | Common Name (CN) CA |
| `organization` | `str` | — | Організація (O) |
| `country` | `str` | — | Дволітерний код країни ISO |
| `key_size` | `int` | `2048` | Довжина RSA-ключа в бітах |
| `days_valid` | `int` | `3650` | Термін дії в днях |

### `ClientConfig`

| Поле | Тип | Замовчування | Опис |
|---|---|---|---|
| `common_name` | `str` | — | CN сертифіката |
| `serial_type` | `CertType` | `SERVICE` | Категорія сертифіката |
| `key_size` | `int` | `2048` | Довжина RSA-ключа |
| `days_valid` | `int` | `365` | Термін дії |
| `email` | `str \| None` | `None` | Атрибут emailAddress в Subject |
| `is_server_cert` | `bool` | `False` | Додає ServerAuth EKU + DNS SAN з CN |
| `is_client_cert` | `bool` | `False` | Додає ClientAuth EKU |
| `san_dns` | `list[str] \| None` | `None` | Додаткові DNS SAN |
| `san_ip` | `list[str] \| None` | `None` | IP-адреси SAN |
| `name` | `str \| None` | `None` | Ім'я вихідного файлу (без розширення) |

### Enum `CertType`

| Значення | Опис |
|---|---|
| `CA` | Кореневий або проміжний CA |
| `USER` | Сертифікат користувача |
| `SERVICE` | Сертифікат сервісу / сервера |
| `DEVICE` | Сертифікат пристрою IoT |
| `INTERNAL` | Внутрішня інфраструктура |

---

## Сховища

### `LocalStorage` (синхронне)

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

Структура директорій:
```
./pki/
└── [cert_path/]
    └── <uuid>/
        ├── service.pem    # x509.Certificate
        ├── service.key    # RSA приватний ключ
        └── service.csr    # CertificateSigningRequest
```

### `AsyncLocalStorage` (асинхронне)

Повна асинхронна заміна `LocalStorage` — той самий конструктор, та сама структура директорій, всі методи I/O є `async`.

---

## Адаптери бази даних

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
await db._db.init_db()  # створення схеми при першому запуску
```

Обидва реалізують `BaseDB`:

| Метод | Опис |
|---|---|
| `get_by_serial(serial)` | Отримати запис за серійним номером X.509 |
| `get_by_name(common_name)` | Отримати активний VALID запис за CN |
| `register_cert_in_db(cert, uuid, key_type)` | Зберегти новий сертифікат |
| `revoke_certificate(serial, reason)` | Позначити сертифікат як відкликаний |
| `get_revoked_certificates()` | Повернути записи для генерації CRL |

---

## Кодування серійного номера

`SerialWithEncoding` упаковує три поля в один 160-бітний цілочисельний номер:

```
[ 16-bit prefix ][ 80-bit name ][ 64-bit random ]
```

- **prefix** — 2-байтний ASCII-код `CertType` (наприклад, `"SV"` для `SERVICE`).
- **name** — до 10 ASCII-символів CN, доповнений нулями.
- **random** — молодші 64 біти нового `uuid.uuid4()`.

```python
from tiny_ca.utils.serial_generator import SerialWithEncoding
from tiny_ca.const import CertType

serial = SerialWithEncoding.generate("nginx", CertType.SERVICE)
cert_type, name = SerialWithEncoding.parse(serial)
# cert_type == CertType.SERVICE
# name == "nginx"
```

---

## Довідник помилок

| Виняток | Коли виникає |
|---|---|
| `DBNotInitedError` | Операція, що потребує БД, викликана без `db_handler` |
| `NotUniqueCertOwner` | Конфлікт CN при `is_overwrite=False` |
| `CertNotFound` | `rotate_certificate` викликано для неіснуючого серійного номера |
| `ValidationCertError` | Невідповідність видавця, строк минув, або помилка перевірки підпису |
| `InvalidRangeTimeCertificate` | Обчислений `not_after` вже в минулому |
| `FileAlreadyExists` | Файл вже існує при `is_overwrite=False` |
| `NotExistCertFile` | Шлях до CA PEM-файлу не існує |
| `IsNotFile` | Шлях існує, але не є звичайним файлом |
| `WrongType` | CA PEM-файл має непідтримуване розширення |
| `ErrorLoadCert` | Помилка десеріалізації PEM |

---

## Запуск тестів

```bash
pip install pytest pytest-cov aiosqlite aiofiles
pytest tests/ --cov=tiny_ca --cov-report=term-missing
```

---

## Структура проекту

```
tiny_ca/
├── ca_factory/
│   ├── factory.py              # CertificateFactory — генерація криптографії
│   └── utils/
│       ├── file_loader.py      # CAFileLoader + протокол ICALoader
│       ├── afile_loader.py     # AsyncCAFileLoader
│       ├── life_time.py        # CertLifetime — допоміжні функції вікна дійсності
│       └── serial.py           # CertSerialParser
├── db/
│   ├── base_db.py              # BaseDB ABC
│   ├── models.py               # ORM-модель CertificateRecord
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
│   ├── const.py                # Аліас типу CryptoObject
│   ├── local_storage.py        # LocalStorage + _CertSerializer
│   └── async_local_storage.py  # AsyncLocalStorage
├── utils/
│   └── serial_generator.py     # SerialGenerator, SerialWithEncoding, _PrefixRegistry
├── const.py                    # Enum CertType
├── exc.py                      # Всі власні винятки
└── settings.py                 # DEFAULT_LOGGER
```
