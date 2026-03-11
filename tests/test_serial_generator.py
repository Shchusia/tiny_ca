"""
test_serial_generator.py

Tests for tiny_ca/utils/serial_generator.py:
  - ISerialGenerator Protocol
  - _PrefixRegistry (forward + reverse lookup, error handling)
  - SerialGenerator  (int path, str path, parse, get_serial_by_name)
  - SerialWithEncoding (generate, parse, round-trip, encoding helpers, masks)
"""

from __future__ import annotations

import pytest

from tiny_ca.const import CertType
from tiny_ca.utils.serial_generator import (
    ISerialGenerator,
    SerialGenerator,
    SerialWithEncoding,
    _PrefixRegistry,
)

# ---------------------------------------------------------------------------
# _PrefixRegistry
# ---------------------------------------------------------------------------


class TestPrefixRegistry:
    def test_prefix_for_ca(self):
        assert _PrefixRegistry.prefix_for(CertType.CA) == 0x4341

    def test_prefix_for_user(self):
        assert _PrefixRegistry.prefix_for(CertType.USER) == 0x5553

    def test_prefix_for_service(self):
        assert _PrefixRegistry.prefix_for(CertType.SERVICE) == 0x5356

    def test_prefix_for_device(self):
        assert _PrefixRegistry.prefix_for(CertType.DEVICE) == 0x4445

    def test_prefix_for_internal(self):
        assert _PrefixRegistry.prefix_for(CertType.INTERNAL) == 0x494E

    def test_type_for_ca_prefix(self):
        assert _PrefixRegistry.type_for(0x4341) is CertType.CA

    def test_type_for_service_prefix(self):
        assert _PrefixRegistry.type_for(0x5356) is CertType.SERVICE

    def test_type_for_unknown_prefix_returns_none(self):
        assert _PrefixRegistry.type_for(0xFFFF) is None

    def test_type_for_zero_returns_none(self):
        assert _PrefixRegistry.type_for(0x0000) is None

    def test_reverse_mapping_covers_all_types(self):
        for ct in CertType:
            prefix = _PrefixRegistry.prefix_for(ct)
            assert _PrefixRegistry.type_for(prefix) is ct

    def test_prefix_for_unknown_type_raises_key_error(self):
        """Passing an object that is not a CertType member raises KeyError."""
        import enum

        class FakeCertType(enum.Enum):
            UNKNOWN = "UNK"

        with pytest.raises(KeyError, match="FakeCertType"):
            _PrefixRegistry.prefix_for(FakeCertType.UNKNOWN)  # type: ignore[arg-type]

    def test_prefix_registry_not_subclassable(self):
        with pytest.raises(TypeError):

            class Sub(_PrefixRegistry):
                pass

    def test_type_to_prefix_is_dict(self):
        assert isinstance(_PrefixRegistry.TYPE_TO_PREFIX, dict)

    def test_prefix_to_type_is_dict(self):
        assert isinstance(_PrefixRegistry.PREFIX_TO_TYPE, dict)

    def test_prefix_to_type_is_inverse_of_type_to_prefix(self):
        for ct, prefix in _PrefixRegistry.TYPE_TO_PREFIX.items():
            assert _PrefixRegistry.PREFIX_TO_TYPE[prefix] is ct


# ---------------------------------------------------------------------------
# SerialGenerator — integer id path
# ---------------------------------------------------------------------------


class TestSerialGeneratorIntPath:
    def setup_method(self):
        self.gen = SerialGenerator()

    def test_generate_returns_int(self):
        s = self.gen.generate(1, CertType.DEVICE)
        assert isinstance(s, int)

    def test_generate_encodes_prefix_in_upper_bits(self):
        s = self.gen.generate(0, CertType.CA)
        prefix = s >> SerialGenerator._DATA_BITS
        assert prefix == 0x4341

    def test_generate_encodes_data_in_lower_bits(self):
        value = 42
        s = self.gen.generate(value, CertType.USER)
        data = s & SerialGenerator._DATA_MASK
        assert data == value

    def test_large_int_truncated_to_48_bits(self):
        big = (1 << 60) + 7
        s = self.gen.generate(big, CertType.DEVICE)
        data = s & SerialGenerator._DATA_MASK
        assert data == big & SerialGenerator._DATA_MASK

    def test_parse_int_returns_cert_type(self):
        s = self.gen.generate(10, CertType.SERVICE)
        ct, _ = self.gen.parse(s)
        assert ct is CertType.SERVICE

    def test_parse_int_user_returns_data_value(self):
        s = self.gen.generate(55, CertType.USER)
        ct, val = self.gen.parse(s)
        assert ct is CertType.USER
        assert val == 55

    def test_parse_non_user_returns_original_value(self):
        s = self.gen.generate(99, CertType.DEVICE)
        ct, val = self.gen.parse(s)
        assert val == 99

    def test_parse_unknown_serial_returns_none_identifier(self):
        ct, val = self.gen.parse(0xDEADBEEF)
        assert val is None

    def test_parse_unknown_prefix_returns_none_type(self):
        ct, _ = self.gen.parse(0x0000FFFFFFFFFFFF)
        assert ct is None


# ---------------------------------------------------------------------------
# SerialGenerator — string id path
# ---------------------------------------------------------------------------


class TestSerialGeneratorStringPath:
    def setup_method(self):
        self.gen = SerialGenerator()

    def test_generate_str_returns_int(self):
        s = self.gen.generate("nginx", CertType.SERVICE)
        assert isinstance(s, int)

    def test_generate_str_counter_starts_at_one(self):
        s = self.gen.generate("first", CertType.SERVICE)
        data = s & SerialGenerator._DATA_MASK
        assert data == 1

    def test_generate_str_counter_increments(self):
        s1 = self.gen.generate("a", CertType.SERVICE)
        s2 = self.gen.generate("b", CertType.SERVICE)
        d1 = s1 & SerialGenerator._DATA_MASK
        d2 = s2 & SerialGenerator._DATA_MASK
        assert d2 == d1 + 1

    def test_different_types_have_independent_counters(self):
        s1 = self.gen.generate("x", CertType.SERVICE)
        s2 = self.gen.generate("y", CertType.DEVICE)
        d1 = s1 & SerialGenerator._DATA_MASK
        d2 = s2 & SerialGenerator._DATA_MASK
        # Both start at 1 independently
        assert d1 == 1
        assert d2 == 1

    def test_parse_str_returns_original_string(self):
        s = self.gen.generate("myservice", CertType.SERVICE)
        ct, val = self.gen.parse(s)
        assert val == "myservice"
        assert ct is CertType.SERVICE

    def test_get_serial_by_name_finds_registered(self):
        s = self.gen.generate("lookup-me", CertType.DEVICE)
        found = self.gen.get_serial_by_name("lookup-me", CertType.DEVICE)
        assert found == s

    def test_get_serial_by_name_wrong_type_returns_none(self):
        self.gen.generate("only-service", CertType.SERVICE)
        result = self.gen.get_serial_by_name("only-service", CertType.DEVICE)
        assert result is None

    def test_get_serial_by_name_not_registered_returns_none(self):
        result = self.gen.get_serial_by_name("never-registered", CertType.CA)
        assert result is None

    def test_multiple_registrations_all_retrievable(self):
        names = ["alpha", "beta", "gamma"]
        serials = [self.gen.generate(n, CertType.INTERNAL) for n in names]
        for name, serial in zip(names, serials):
            assert self.gen.get_serial_by_name(name, CertType.INTERNAL) == serial


# ---------------------------------------------------------------------------
# SerialWithEncoding — generate / parse round-trips
# ---------------------------------------------------------------------------


class TestSerialWithEncodingRoundTrip:
    @pytest.mark.parametrize(
        "name,cert_type",
        [
            ("nginx", CertType.DEVICE),
            ("my-service", CertType.SERVICE),
            ("ca-root", CertType.CA),
            ("user1", CertType.USER),
            ("int-node", CertType.INTERNAL),
            ("a", CertType.CA),  # single char
            ("0123456789", CertType.DEVICE),  # exactly MAX_NAME_LENGTH
        ],
    )
    def test_round_trip(self, name, cert_type):
        serial = SerialWithEncoding.generate(name, cert_type)
        decoded_type, decoded_name = SerialWithEncoding.parse(serial)
        assert decoded_type is cert_type
        assert decoded_name == name

    def test_long_name_truncated_to_max(self):
        long_name = "abcdefghijklmnop"  # 16 chars > MAX_NAME_LENGTH=10
        serial = SerialWithEncoding.generate(long_name, CertType.SERVICE)
        _, decoded = SerialWithEncoding.parse(serial)
        assert decoded == long_name[: SerialWithEncoding.MAX_NAME_LENGTH]

    def test_uniqueness_same_name_same_type(self):
        s1 = SerialWithEncoding.generate("same", CertType.CA)
        s2 = SerialWithEncoding.generate("same", CertType.CA)
        # 64-bit random segment makes collision virtually impossible
        assert s1 != s2

    def test_serial_fits_in_160_bits(self):
        serial = SerialWithEncoding.generate("test", CertType.CA)
        assert serial.bit_length() <= 160

    def test_serial_is_positive(self):
        serial = SerialWithEncoding.generate("test", CertType.CA)
        assert serial > 0

    def test_parse_unknown_prefix_returns_none_type(self):
        # Manually craft a serial with an unknown prefix
        unknown_prefix = 0x1234
        serial = unknown_prefix << (
            SerialWithEncoding.NAME_BITS + SerialWithEncoding.RANDOM_BITS
        )
        ct, _ = SerialWithEncoding.parse(serial)
        assert ct is None

    def test_empty_name_round_trips(self):
        serial = SerialWithEncoding.generate("", CertType.CA)
        _, decoded = SerialWithEncoding.parse(serial)
        assert decoded == ""


# ---------------------------------------------------------------------------
# SerialWithEncoding — internal helpers
# ---------------------------------------------------------------------------


class TestSerialWithEncodingHelpers:
    def test_encode_name_single_char(self):
        val = SerialWithEncoding._encode_name("A")
        assert val == ord("A")

    def test_encode_name_two_chars_little_endian(self):
        val = SerialWithEncoding._encode_name("AB")
        assert val == ord("A") | (ord("B") << 8)

    def test_encode_name_empty_string(self):
        assert SerialWithEncoding._encode_name("") == 0

    def test_encode_name_too_long_raises(self):
        too_long = "x" * (SerialWithEncoding.MAX_NAME_LENGTH + 1)
        with pytest.raises(ValueError, match="too long"):
            SerialWithEncoding._encode_name(too_long)

    def test_encode_name_exactly_max_length_ok(self):
        name = "a" * SerialWithEncoding.MAX_NAME_LENGTH
        val = SerialWithEncoding._encode_name(name)
        assert isinstance(val, int)

    def test_decode_name_single_char(self):
        val = ord("Z")
        assert SerialWithEncoding._decode_name(val, 10) == "Z"

    def test_decode_name_empty_value_returns_empty(self):
        assert SerialWithEncoding._decode_name(0, 10) == ""

    def test_decode_name_null_byte_terminates_early(self):
        # Pack "AB" then zero, then "C" — should stop at zero
        val = ord("A") | (ord("B") << 8) | (0 << 16) | (ord("C") << 24)
        result = SerialWithEncoding._decode_name(val, 10)
        assert result == "AB"

    def test_random_mask_correct_bits(self):
        mask = SerialWithEncoding._random_mask()
        assert mask == (1 << SerialWithEncoding.RANDOM_BITS) - 1

    def test_name_mask_correct_bits(self):
        mask = SerialWithEncoding._name_mask()
        assert mask == (1 << SerialWithEncoding.NAME_BITS) - 1

    def test_random_mask_does_not_overlap_name_mask(self):
        r = SerialWithEncoding._random_mask()
        n = SerialWithEncoding._name_mask() << SerialWithEncoding.RANDOM_BITS
        assert (r & n) == 0

    def test_constants_sum_to_160_bits(self):
        total = 16 + SerialWithEncoding.NAME_BITS + SerialWithEncoding.RANDOM_BITS
        assert total == 160


# ---------------------------------------------------------------------------
# ISerialGenerator Protocol compliance
# ---------------------------------------------------------------------------


class TestISerialGeneratorProtocol:
    def test_serial_with_encoding_satisfies_protocol(self):
        assert isinstance(SerialWithEncoding, ISerialGenerator)

    def test_serial_generator_satisfies_protocol(self):
        gen = SerialGenerator()
        assert isinstance(gen, ISerialGenerator)

    def test_plain_object_does_not_satisfy_protocol(self):
        assert not isinstance(object(), ISerialGenerator)

    def test_class_without_parse_does_not_satisfy(self):
        class OnlyGenerate:
            @staticmethod
            def generate(name, serial_type):
                return 0

        assert not isinstance(OnlyGenerate(), ISerialGenerator)
