"""
audit.py

Tamper-evident audit log for CA operations.

Every security-relevant operation (CA creation, issuance, renewal, rotation,
co-signing, revocation, deletion, CRL generation, PKCS#12 export) can be
appended to an :class:`AuditLog`.  The log is a JSON-Lines file in which

* every entry carries a sequence number, a UTC timestamp, the actor, the
  event name and its data;
* every entry includes the SHA-256 hash of the previous entry (``prev``) and
  its own hash (``hash``), forming a hash chain — editing, inserting,
  reordering or deleting an entry in the middle breaks the chain;
* every entry can be signed (``sig``) with a dedicated audit key or any
  :class:`~tiny_ca.signing.CASigner` (e.g. an HSM), so the chain cannot be
  silently recomputed by someone who can write the file but does not hold
  the key.

Truncation of the *tail* can only be detected against a head hash stored
elsewhere: periodically publish :attr:`AuditLog.head` (ticketing system,
SIEM, a second host) and pass it to :meth:`AuditLog.verify` as
``expected_head``.

Writes are serialised with a thread lock and, on POSIX, an exclusive
``flock`` so that several processes on one host can share a log file.
``flock`` is advisory and unreliable on network file systems; on Windows
there is no inter-process lock — use one writer process there.

An entry is written only after the audited operation has completed, so a
failure to write it (``AuditLogError``) means the operation took effect but
is not recorded: treat it as an incident, do not simply retry.  A crash in
the middle of a write leaves an unterminated last line; the next
:meth:`AuditLog.record` cuts it off and records an
``audit.torn_entry_removed`` event with its size and SHA-256.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator, Mapping
import datetime
import getpass
import hashlib
import json
from logging import Logger
import os
from pathlib import Path
import threading
from typing import IO, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from tiny_ca.exc import AuditLogError
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.signing import CASigner, KeySigner, verify_signature
from tiny_ca.utils.keys import PrivateKey, PublicKey, signing_hash

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

__all__ = ["AuditLog", "GENESIS_HASH", "certificate_fields", "crl_fields"]

#: ``prev`` value of the first entry.
GENESIS_HASH = "0" * 64

_FILE_MODE = 0o640
_TAIL_BLOCK = 4096


def certificate_fields(cert: x509.Certificate) -> dict[str, Any]:
    """Standard audit fields describing *cert*."""
    return {
        "serial": str(cert.serial_number),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_after": cert.not_valid_after_utc.isoformat(),
    }


def crl_fields(crl: x509.CertificateRevocationList) -> dict[str, Any]:
    """Standard audit fields describing *crl*."""
    try:
        number: str | None = str(
            crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        )
    except x509.ExtensionNotFound:
        number = None
    next_update = crl.next_update_utc
    return {
        "crl_number": number,
        "issuer": crl.issuer.rfc4514_string(),
        "revoked": len(crl),
        "next_update": next_update.isoformat() if next_update else None,
        "sha256": hashlib.sha256(
            crl.public_bytes(serialization.Encoding.DER)
        ).hexdigest(),
    }


def _canonical(entry: Mapping[str, Any]) -> bytes:
    return json.dumps(
        entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _entry_hash(entry: Mapping[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k not in ("hash", "sig")}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _default_actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - no user database (containers)
        return f"uid:{os.getuid()}" if hasattr(os, "getuid") else "unknown"


def _last_line(f: IO[bytes]) -> bytes | None:
    """
    Return the last complete, non-empty line of *f* (reading backwards in
    blocks).  An unterminated trailing fragment is ignored.
    """
    pos = f.seek(0, os.SEEK_END)
    buf = b""
    while True:
        last_nl = buf.rfind(b"\n")
        if last_nl != -1:
            body = buf[:last_nl].rstrip(b"\n")
            cut = body.rfind(b"\n")
            if cut != -1:
                return body[cut + 1 :]
            if pos == 0:
                return body or None
        elif pos == 0:
            return None
        step = min(_TAIL_BLOCK, pos)
        pos -= step
        f.seek(pos)
        buf = f.read(step) + buf


def _cut_torn_tail(f: IO[bytes]) -> bytes | None:
    """Truncate an unterminated last line of *f* and return it (or None)."""
    end = f.seek(0, os.SEEK_END)
    if end == 0:
        return None
    f.seek(end - 1)
    if f.read(1) == b"\n":
        return None
    pos = end
    cut = 0
    while pos > 0:
        step = min(_TAIL_BLOCK, pos)
        pos -= step
        f.seek(pos)
        index = f.read(step).rfind(b"\n")
        if index != -1:
            cut = pos + index + 1
            break
    f.seek(cut)
    torn = f.read()
    f.truncate(cut)
    return torn


class AuditLog:
    """
    Append-only, hash-chained and optionally signed audit log.

    Parameters
    ----------
    path : str | Path
        Log file (JSON Lines).  Created with mode ``0640`` if missing.
    signer : PrivateKey | CASigner | None
        Key used to sign every entry.  Use a dedicated audit key (or a key
        on an HSM via :class:`~tiny_ca.signing.Pkcs11Signer`), not the CA
        key.  ``None`` keeps the hash chain but adds no signatures.
    actor : str | None
        Who performs the operations (operator, service account).  Defaults
        to the OS user name.  Can be overridden per entry.
    logger : Logger | None
        Logger for diagnostics.  Falls back to ``DEFAULT_LOGGER``.
    """

    def __init__(
        self,
        path: str | Path,
        signer: PrivateKey | CASigner | None = None,
        actor: str | None = None,
        logger: Logger | None = None,
    ) -> None:
        self.path = Path(path)
        # Private keys also look like a CASigner (public_key() / sign()),
        # so test for them first.
        if isinstance(signer, PrivateKey):
            self._signer: CASigner | None = KeySigner(signer)
        else:
            self._signer = signer
        self.actor = actor or _default_actor()
        self._logger = logger or DEFAULT_LOGGER
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def record(
        self,
        event: str,
        data: Mapping[str, Any] | None = None,
        *,
        actor: str | None = None,
    ) -> dict[str, Any]:
        """
        Append an entry and return it.

        Values in *data* that are not JSON types are stored as ``str()``.

        Raises
        ------
        AuditLogError
            If the file cannot be written, its last entry is unreadable, or
            the signer fails.  The caller should treat this as fatal: an
            operation that cannot be audited should not be considered done.
        """
        with self._lock:
            try:
                with self._open() as f:
                    torn = _cut_torn_tail(f)
                    if torn is not None:
                        self._logger.error(
                            "Audit log %s ended with an unterminated entry "
                            "(%d bytes); it was removed",
                            self.path,
                            len(torn),
                        )
                        self._append(
                            f,
                            "audit.torn_entry_removed",
                            {
                                "bytes": len(torn),
                                "sha256": hashlib.sha256(torn).hexdigest(),
                            },
                            self.actor,
                        )
                    entry = self._append(f, event, data, actor or self.actor)
            except AuditLogError:
                raise
            except Exception as exc:
                raise AuditLogError(f"cannot write audit entry: {exc}") from exc
        self._logger.debug("Audit: %s seq=%d", event, entry["seq"])
        return entry

    def _append(
        self,
        f: IO[bytes],
        event: str,
        data: Mapping[str, Any] | None,
        actor: str,
    ) -> dict[str, Any]:
        seq, prev = self._tail(f)
        entry: dict[str, Any] = json.loads(
            json.dumps(
                {
                    "seq": seq,
                    "ts": datetime.datetime.now(datetime.UTC).isoformat(),
                    "actor": actor,
                    "event": event,
                    "data": dict(data or {}),
                    "prev": prev,
                },
                default=str,
            )
        )
        entry["hash"] = _entry_hash(entry)
        if self._signer is not None:
            entry["sig"] = self._sign(self._signer, entry["hash"])
        f.write(_canonical(entry) + b"\n")
        f.flush()
        os.fsync(f.fileno())
        return entry

    def _open(self) -> _LockedFile:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, _FILE_MODE)
        return _LockedFile(os.fdopen(fd, "r+b"))

    @staticmethod
    def _tail(f: IO[bytes]) -> tuple[int, str]:
        line = _last_line(f)
        if line is None:
            return 0, GENESIS_HASH
        try:
            last = json.loads(line)
            return int(last["seq"]) + 1, str(last["hash"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditLogError(
                f"last audit entry is corrupt, refusing to append: {exc}"
            ) from exc

    @staticmethod
    def _sign(signer: CASigner, digest_hex: str) -> str:
        algorithm = signing_hash(signer.public_key())
        return base64.b64encode(signer.sign(digest_hex.encode(), algorithm)).decode()

    # ------------------------------------------------------------------
    # Reading / verification
    # ------------------------------------------------------------------

    @property
    def head(self) -> str:
        """Hash of the last entry (``GENESIS_HASH`` for an empty log)."""
        if not self.path.exists():
            return GENESIS_HASH
        with _LockedFile(self.path.open("rb"), shared=True) as f:
            return self._tail(f)[1]

    @staticmethod
    def entries(path: str | Path) -> Iterator[dict[str, Any]]:
        """Iterate over the parsed entries of the log at *path*."""
        with Path(path).open("rb") as f:
            for number, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except ValueError as exc:
                    raise AuditLogError(f"line {number}: not valid JSON") from exc
                if not isinstance(entry, dict):
                    raise AuditLogError(f"line {number}: not a JSON object")
                yield entry

    @classmethod
    def verify(
        cls,
        path: str | Path,
        public_key: PublicKey | x509.Certificate | None = None,
        expected_head: str | None = None,
    ) -> int:
        """
        Verify the hash chain (and signatures) of the log at *path*.

        Parameters
        ----------
        public_key : PublicKey | x509.Certificate | None
            When given, every entry must carry a valid signature by the
            matching private key.
        expected_head : str | None
            Head hash recorded out of band; detects truncation of the tail.

        Returns
        -------
        int
            Number of verified entries.

        Raises
        ------
        AuditLogError
            On the first broken link, bad hash, missing or invalid signature,
            or head mismatch.
        """
        if isinstance(public_key, x509.Certificate):
            public_key = public_key.public_key()  # type: ignore[assignment]
        algorithm = (
            signing_hash(public_key)  # type: ignore[arg-type]
            if public_key is not None
            else None
        )
        prev, count = GENESIS_HASH, 0
        for entry in cls.entries(path):
            where = f"entry seq={entry.get('seq')!r}"
            if entry.get("seq") != count:
                raise AuditLogError(f"{where}: expected seq={count}")
            if entry.get("prev") != prev:
                raise AuditLogError(f"{where}: chain broken (prev hash mismatch)")
            if entry.get("hash") != _entry_hash(entry):
                raise AuditLogError(f"{where}: content does not match its hash")
            if public_key is not None:
                try:
                    signature = base64.b64decode(entry["sig"], validate=True)
                except (KeyError, ValueError, TypeError):
                    raise AuditLogError(f"{where}: missing signature") from None
                if not verify_signature(
                    public_key,  # type: ignore[arg-type]
                    signature,
                    entry["hash"].encode(),
                    algorithm,
                ):
                    raise AuditLogError(f"{where}: invalid signature")
            prev = entry["hash"]
            count += 1
        if expected_head is not None and prev != expected_head:
            raise AuditLogError(
                "log head does not match the expected head (truncated or replaced)"
            )
        return count


class _LockedFile:
    """Context manager holding an exclusive (or shared) ``flock`` on a file."""

    def __init__(self, f: IO[bytes], shared: bool = False) -> None:
        self._f = f
        self._shared = shared

    def __enter__(self) -> IO[bytes]:
        if fcntl is not None:  # pragma: no branch
            fcntl.flock(
                self._f.fileno(), fcntl.LOCK_SH if self._shared else fcntl.LOCK_EX
            )
        return self._f

    def __exit__(self, *exc_info: object) -> None:
        try:
            if fcntl is not None:  # pragma: no branch
                fcntl.flock(self._f.fileno(), fcntl.LOCK_UN)
        finally:
            self._f.close()
