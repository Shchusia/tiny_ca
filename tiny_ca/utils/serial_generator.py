"""
serial_generator.py

X.509 certificate serial number generation and parsing utilities.

Two implementations are provided:

- ``SerialGenerator``      — stateful generator that maintains an internal
                             mapping between serial numbers and their source
                             identifiers (int or str).  Suitable when an
                             authoritative in-process registry is acceptable.

- ``SerialWithEncoding``   — stateless generator that encodes a short name
                             prefix and a random UUID fragment into a single
                             integer.  No shared state; safe for concurrent use.

SOLID compliance
----------------
SRP : Each class has a single reason to change.
      ``SerialGenerator``    → manages serial ↔ id mapping.
      ``SerialWithEncoding`` → encodes/decodes name + random bits.
      ``_PrefixRegistry``    → owns the CertType ↔ hex-prefix mapping.
OCP : New ``CertType`` variants require only a new entry in ``_PrefixRegistry``;
      no existing logic changes.
LSP : Both generators expose compatible ``generate`` / ``parse`` signatures,
      so they can be swapped behind an ``ISerialGenerator`` Protocol.
ISP : ``ISerialGenerator`` declares only the two methods callers actually need.
DIP : ``CertificateFactory`` (and other consumers) depend on ``ISerialGenerator``,
      not on concrete classes.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable
import uuid

from tiny_ca.const import CertType

# ---------------------------------------------------------------------------
# ISP / DIP: minimal interface that callers depend on
# ---------------------------------------------------------------------------


@runtime_checkable
class ISerialGenerator(Protocol):
    """
    Minimal contract for serial-number generators.

    Any class that exposes ``generate`` and ``parse`` with compatible
    signatures satisfies this Protocol and can be injected wherever
    certificate serial numbers are needed.
    """

    @staticmethod
    def generate(name: str, serial_type: CertType) -> int:
        """
        Generate a unique serial number for the given name and certificate type.

        Parameters
        ----------
        name : str
            Human-readable identifier (e.g. CN or service name).
        serial_type : CertType
            Category of the certificate (CA, USER, SERVICE, …).

        Returns
        -------
        int
            A non-negative integer suitable for use as an X.509 serial number.
        """
        ...

    @staticmethod
    def parse(serial: int) -> tuple[CertType, str]:
        """
        Decode a previously generated serial number.

        Parameters
        ----------
        serial : int
            Integer serial number produced by ``generate``.

        Returns
        -------
        tuple[CertType, str]
            ``(cert_type, name)`` recovered from the serial.
        """
        ...


# ---------------------------------------------------------------------------
# OCP: centralised prefix registry — add new types here only
# ---------------------------------------------------------------------------


class _PrefixRegistry:
    """
    Bidirectional mapping between :class:`CertType` and 2-byte hex prefixes.

    The prefixes are chosen to be human-readable in hex dumps:

    ========== ======= ========
    CertType   Prefix  ASCII
    ========== ======= ========
    CA         0x4341  "CA"
    USER       0x5553  "US"
    SERVICE    0x5356  "SV"
    DEVICE     0x4445  "DE"
    INTERNAL   0x494E  "IN"
    ========== ======= ========

    Class is intentionally non-instantiable (all attributes are class-level).
    """

    #: ``CertType`` → 2-byte integer prefix (big-endian ASCII representation).
    TYPE_TO_PREFIX: dict[CertType, int] = {
        CertType.CA: 0x4341,  # "CA"
        CertType.USER: 0x5553,  # "US"
        CertType.SERVICE: 0x5356,  # "SV"
        CertType.DEVICE: 0x4445,  # "DE"
        CertType.INTERNAL: 0x494E,  # "IN"
    }

    #: Reverse mapping: 2-byte prefix → ``CertType``.
    PREFIX_TO_TYPE: dict[int, CertType] = {v: k for k, v in TYPE_TO_PREFIX.items()}

    def __init_subclass__(cls, **kwargs: object) -> None:  # pragma: no cover
        raise TypeError("_PrefixRegistry is not meant to be subclassed.")

    @classmethod
    def prefix_for(cls, cert_type: CertType) -> int:
        """
        Return the numeric prefix for *cert_type*.

        Parameters
        ----------
        cert_type : CertType
            The certificate category to look up.

        Returns
        -------
        int
            2-byte integer prefix.

        Raises
        ------
        KeyError
            If *cert_type* has no registered prefix.
        """
        try:
            return cls.TYPE_TO_PREFIX[cert_type]
        except KeyError:
            raise KeyError(
                f"No prefix registered for CertType.{cert_type.name}. "
                "Add it to _PrefixRegistry.TYPE_TO_PREFIX."
            ) from None

    @classmethod
    def type_for(cls, prefix: int) -> CertType | None:
        """
        Return the :class:`CertType` associated with *prefix*, or ``None``.

        Parameters
        ----------
        prefix : int
            2-byte integer prefix extracted from a serial number.

        Returns
        -------
        CertType | None
            Matching certificate type, or ``None`` if the prefix is unknown.
        """
        return cls.PREFIX_TO_TYPE.get(prefix)


# ---------------------------------------------------------------------------
# SRP: stateful serial generator with id ↔ serial mapping
# ---------------------------------------------------------------------------


class SerialGenerator:
    """
    Stateful serial-number generator with a bidirectional id ↔ serial registry.

    Serial number layout (64-bit integer)
    ::

        [ 16-bit prefix ][ 48-bit data ]

    - **prefix** — 2-byte ASCII code derived from :class:`CertType`
      (see :class:`_PrefixRegistry`).
    - **data**   — for ``int`` inputs: the value itself (truncated to 48 bits);
                   for ``str`` inputs: an auto-incrementing counter per type.

    The mapping between serial numbers and their original identifiers is kept
    in instance-level dictionaries, making this class unsuitable for concurrent
    multi-process use without external synchronisation.

    Attributes
    ----------
    _id_map : dict[int, int | str]
        Maps ``serial`` → original identifier (int or str).
    _name_map : dict[str, int]
        Maps ``"<cert_type_value>_<name>"`` → serial; populated for string ids.
    _last_serial : dict[CertType, int]
        Per-type auto-increment counter for string-based identifiers.
    """

    #: Bit-width reserved for the data portion of the serial.
    _DATA_BITS: int = 48

    #: Bitmask for the data portion: ``(1 << 48) - 1``.
    _DATA_MASK: int = (1 << _DATA_BITS) - 1

    def __init__(self) -> None:
        self._id_map: dict[int, int | str] = {}
        self._name_map: dict[str, int] = {}
        self._last_serial: dict[CertType, int] = {}

    # ------------------------------------------------------------------
    # ISerialGenerator interface
    # ------------------------------------------------------------------

    def generate(self, id_value: int | str, serial_type: CertType) -> int:
        """
        Generate a serial number for *id_value* and register the mapping.

        For **integer** inputs the value is embedded directly into the data
        field (truncated to 48 bits).  For **string** inputs a per-type
        auto-increment counter is used and the original string is stored in
        ``_id_map`` for later retrieval by :meth:`parse`.

        Parameters
        ----------
        id_value : int | str
            Source identifier.  Integers are encoded directly; strings trigger
            the auto-increment path.
        serial_type : CertType
            Certificate category; determines the 2-byte prefix.

        Returns
        -------
        int
            64-bit serial number: ``(prefix << 48) | data``.

        Raises
        ------
        KeyError
            If *serial_type* has no registered prefix.
        """
        prefix = _PrefixRegistry.prefix_for(serial_type)

        if isinstance(id_value, int):
            data = id_value & self._DATA_MASK
            serial = (prefix << self._DATA_BITS) | data
            self._id_map[serial] = id_value
        else:
            counter = self._last_serial.get(serial_type, 1)
            data = counter & self._DATA_MASK
            serial = (prefix << self._DATA_BITS) | data

            self._id_map[serial] = id_value
            self._name_map[f"{serial_type.value}_{id_value}"] = serial
            self._last_serial[serial_type] = counter + 1

        return serial

    def parse(self, serial: int) -> tuple[CertType | None, int | str | None]:
        """
        Decode a serial number back to its type and original identifier.

        For ``CertType.USER`` the numeric data portion is returned directly.
        For all other types the original identifier is looked up from the
        internal registry; ``None`` is returned if not found.

        Parameters
        ----------
        serial : int
            64-bit serial number previously produced by :meth:`generate`.

        Returns
        -------
        tuple[CertType | None, int | str | None]
            ``(cert_type, original_id)``.  Both members may be ``None`` if
            the serial was not generated by this instance.
        """
        prefix = serial >> self._DATA_BITS
        data = serial & self._DATA_MASK
        cert_type = _PrefixRegistry.type_for(prefix)

        if cert_type == CertType.USER:
            return cert_type, data

        return cert_type, self._id_map.get(serial)

    def get_serial_by_name(self, name: str, serial_type: CertType) -> int | None:
        """
        Look up the serial number previously assigned to a string identifier.

        Parameters
        ----------
        name : str
            Original string identifier passed to :meth:`generate`.
        serial_type : CertType
            Certificate type under which the name was registered.

        Returns
        -------
        int | None
            Registered serial number, or ``None`` if not found.
        """
        return self._name_map.get(f"{serial_type.value}_{name}")


# ---------------------------------------------------------------------------
# SRP: stateless serial generator with name encoding + UUID randomness
# ---------------------------------------------------------------------------


class SerialWithEncoding:
    """
    Stateless serial-number generator that encodes a short name prefix and
    a UUID-derived random fragment into a single integer.

    Serial number layout
    ::

        [ 16-bit prefix ][ 80-bit encoded name ][ 64-bit random ]

    Total width: **160 bits** (well within Python's arbitrary-precision int;
    X.509 allows up to 20 bytes / 160 bits per RFC 5280 §4.1.2.2).

    - **prefix**       — 2-byte ASCII code from :class:`_PrefixRegistry`.
    - **encoded name** — up to 4 ASCII characters packed into 32 bits
                         (little-endian byte order, zero-padded).
    - **random**       — lower 64 bits of a fresh ``uuid.uuid4()`` ensuring
                         global uniqueness without shared state.

    Because no mutable state is kept, this class is safe to use from multiple
    threads or processes simultaneously.

    Class Attributes
    ----------------
    RANDOM_BITS : int
        Number of bits reserved for the random (UUID) portion. Default: ``64``.
    NAME_BITS : int
        Number of bits reserved for the encoded name portion. Default: ``32``
        (4 bytes × 8 bits).
    MAX_NAME_LENGTH : int
        Maximum number of ASCII characters that can be encoded. Default: ``4``.
    """

    #: Bit-width of the random (UUID) segment.
    RANDOM_BITS: int = 64

    #: Bit-width of the encoded-name segment (10 ASCII chars × 8 bits).
    NAME_BITS: int = 80

    #: Maximum number of characters accepted by :meth:`_encode_name`.
    MAX_NAME_LENGTH: int = 10

    # ------------------------------------------------------------------
    # ISerialGenerator interface
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls, name: str, serial_type: CertType) -> int:
        """
        Generate a globally unique serial number for *name* and *serial_type*.

        Only the first :attr:`MAX_NAME_LENGTH` characters of *name* are encoded;
        uniqueness is guaranteed by the UUID random segment, not by the name.

        Parameters
        ----------
        name : str
            Human-readable identifier.  Only the first 4 ASCII characters are
            embedded; the remainder is ignored (not hashed or truncated with loss).
        serial_type : CertType
            Certificate category; determines the 2-byte prefix.

        Returns
        -------
        int
            Non-negative integer serial suitable for X.509 certificates.

        Raises
        ------
        KeyError
            If *serial_type* has no registered prefix.

        Examples
        --------
        >>> serial = SerialWithEncoding.generate("nginx", CertType.SERVICE)
        >>> cert_type, name = SerialWithEncoding.parse(serial)
        >>> assert cert_type == CertType.SERVICE
        >>> assert name == "ngin"  # only first 4 chars are stored
        """
        prefix: int = _PrefixRegistry.prefix_for(serial_type)
        encoded_name: int = cls._encode_name(name[: cls.MAX_NAME_LENGTH])
        random_part: int = uuid.uuid4().int & cls._random_mask()

        serial: int = (
            (prefix << (cls.NAME_BITS + cls.RANDOM_BITS))
            | (encoded_name << cls.RANDOM_BITS)
            | random_part
        )
        return serial

    @classmethod
    def parse(cls, serial: int) -> tuple[CertType | None, str]:
        """
        Decode a serial number produced by :meth:`generate`.

        Parameters
        ----------
        serial : int
            Integer serial number to decode.

        Returns
        -------
        tuple[CertType | None, str]
            ``(cert_type, name_prefix)`` where *name_prefix* is the up-to-4-char
            string recovered from the encoded-name segment.
            *cert_type* is ``None`` if the prefix is unrecognised.

        Examples
        --------
        >>> serial = SerialWithEncoding.generate("ca-root", CertType.CA)
        >>> cert_type, name = SerialWithEncoding.parse(serial)
        >>> assert cert_type == CertType.CA
        >>> assert name == "ca-r"
        """
        random_part: int = serial & cls._random_mask()  # noqa: F841 — kept for clarity
        encoded_name: int = (serial >> cls.RANDOM_BITS) & cls._name_mask()
        prefix: int = serial >> (cls.RANDOM_BITS + cls.NAME_BITS)

        cert_type: CertType | None = _PrefixRegistry.type_for(prefix)
        name: str = cls._decode_name(encoded_name, cls.MAX_NAME_LENGTH)

        return cert_type, name

    # ------------------------------------------------------------------
    # Private encoding helpers
    # ------------------------------------------------------------------

    @classmethod
    def _encode_name(cls, text: str) -> int:
        """
        Pack up to :attr:`MAX_NAME_LENGTH` ASCII characters into a single integer.

        Characters are stored in **little-endian** byte order:
        ``result |= ord(char) << (8 * position)``.

        Parameters
        ----------
        text : str
            ASCII string of length ≤ :attr:`MAX_NAME_LENGTH`.

        Returns
        -------
        int
            Non-negative integer with characters packed into the lower bytes.

        Raises
        ------
        ValueError
            If *text* is longer than :attr:`MAX_NAME_LENGTH`.
        """
        if len(text) > cls.MAX_NAME_LENGTH:
            raise ValueError(
                f"Name too long: {len(text)} chars > {cls.MAX_NAME_LENGTH} max. "
                f"Truncate before calling or increase MAX_NAME_LENGTH."
            )
        result: int = 0
        for position, char in enumerate(text):
            result |= ord(char) << (8 * position)
        return result

    @classmethod
    def _decode_name(cls, value: int, length: int) -> str:
        """
        Unpack a little-endian-encoded integer back into an ASCII string.

        Null bytes (``0x00``) terminate the string early, so zero-padding
        introduced by :meth:`_encode_name` is stripped automatically.

        Parameters
        ----------
        value : int
            Integer produced by :meth:`_encode_name`.
        length : int
            Maximum number of characters to attempt to decode.

        Returns
        -------
        str
            Decoded ASCII string with trailing null characters removed.
        """
        chars: list[str] = []
        for position in range(length):
            byte: int = (value >> (8 * position)) & 0xFF
            if byte == 0:
                break
            chars.append(chr(byte))
        return "".join(chars)

    @classmethod
    def _random_mask(cls) -> int:
        """
        Bitmask for the random segment: ``(1 << RANDOM_BITS) - 1``.

        Returns
        -------
        int
            Integer with the lower :attr:`RANDOM_BITS` set to 1.
        """
        return (1 << cls.RANDOM_BITS) - 1

    @classmethod
    def _name_mask(cls) -> int:
        """
        Bitmask for the name segment: ``(1 << NAME_BITS) - 1``.

        Returns
        -------
        int
            Integer with the lower :attr:`NAME_BITS` set to 1.
        """
        return (1 << cls.NAME_BITS) - 1


if __name__ == "__main__":
    # SerialWithEncoding round-trip
    serial = SerialWithEncoding.generate("nginx", CertType.DEVICE)
    s_type, recovered_name = SerialWithEncoding.parse(serial)
    print(f"serial  : {serial}")
    print(f"hex     : {hex(serial)}")
    print(f"type    : {s_type}")
    print(f"name    : {recovered_name}")  # expected: "ngin" (first 4 chars)

    # SerialGenerator round-trip
    gen = SerialGenerator()
    s1 = gen.generate("my-service", CertType.SERVICE)
    s2 = gen.generate(42, CertType.USER)
    print("\nSerialGenerator:")
    print(f"  string serial → {gen.parse(s1)}")
    print(f"  int serial    → {gen.parse(s2)}")
