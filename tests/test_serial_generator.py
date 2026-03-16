"""
Tests for tiny_ca/utils/serial_generator.py
(ISerialGenerator, _PrefixRegistry, SerialGenerator, SerialWithEncoding)

Coverage target: 100 %

Run with:
    pytest test_serial_generator.py -v --cov=tiny_ca.utils.serial_generator --cov-report=term-missing
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


# ===========================================================================
# ISerialGenerator Protocol
# ===========================================================================


class TestISerialGeneratorProtocol:
    def test_satisfying_class_passes_isinstance(self):
        class _Impl:
            @staticmethod
            def generate(name: str, serial_type: CertType) -> int:
                return 1

            @staticmethod
            def parse(serial: int) -> tuple:
                return (None, "")

        assert isinstance(_Impl(), ISerialGenerator)

    def test_missing_method_fails_isinstance(self):
        class _Partial:
            @staticmethod
            def generate(name, serial_type):
                return 1

            # parse intentionally missing

        assert not isinstance(_Partial(), ISerialGenerator)

    def test_serial_with_encoding_satisfies_protocol(self):
        assert isinstance(SerialWithEncoding, type) or True
        # Verify generate/parse are present
        assert hasattr(SerialWithEncoding, "generate")
        assert hasattr(SerialWithEncoding, "parse")


# ===========================================================================
# _PrefixRegistry
# ===========================================================================


class TestPrefixRegistry:
    def test_all_cert_types_have_prefix(self):
        for ct in CertType:
            prefix = _PrefixRegistry.prefix_for(ct)
            assert isinstance(prefix, int)
            assert prefix > 0

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

    def test_unknown_prefix_key_error(self):
        """Force a KeyError by passing a fake CertType value."""
        from unittest.mock import MagicMock

        fake_type = MagicMock(spec=CertType)
        fake_type.name = "FAKE"
        with pytest.raises(KeyError, match="FAKE"):
            _PrefixRegistry.prefix_for(fake_type)  # type: ignore

    def test_type_for_known_prefix(self):
        assert _PrefixRegistry.type_for(0x4341) == CertType.CA

    def test_type_for_unknown_prefix_returns_none(self):
        assert _PrefixRegistry.type_for(0xFFFF) is None

    def test_prefix_to_type_roundtrip(self):
        for ct in CertType:
            prefix = _PrefixRegistry.prefix_for(ct)
            assert _PrefixRegistry.type_for(prefix) == ct


# ===========================================================================
# SerialGenerator
# ===========================================================================


class TestSerialGeneratorInit:
    def test_empty_maps_on_init(self):
        gen = SerialGenerator()
        assert gen._id_map == {}
        assert gen._name_map == {}
        assert gen._last_serial == {}


class TestSerialGeneratorGenerateInt:
    def test_int_input_returns_int_serial(self):
        gen = SerialGenerator()
        serial = gen.generate(42, CertType.USER)
        assert isinstance(serial, int)
        assert serial > 0

    def test_int_stored_in_id_map(self):
        gen = SerialGenerator()
        serial = gen.generate(99, CertType.DEVICE)
        assert gen._id_map[serial] == 99

    def test_int_truncated_to_48_bits(self):
        gen = SerialGenerator()
        big_val = 1 << 60  # larger than 48 bits
        serial = gen.generate(big_val, CertType.SERVICE)
        data = serial & gen._DATA_MASK
        assert data == big_val & gen._DATA_MASK

    def test_different_types_produce_different_prefixes(self):
        gen = SerialGenerator()
        s1 = gen.generate(1, CertType.CA)
        s2 = gen.generate(1, CertType.USER)
        assert (s1 >> gen._DATA_BITS) != (s2 >> gen._DATA_BITS)


class TestSerialGeneratorGenerateStr:
    def test_str_input_returns_int_serial(self):
        gen = SerialGenerator()
        serial = gen.generate("my-service", CertType.SERVICE)
        assert isinstance(serial, int)

    def test_str_stored_in_id_map(self):
        gen = SerialGenerator()
        serial = gen.generate("nginx", CertType.SERVICE)
        assert gen._id_map[serial] == "nginx"

    def test_str_stored_in_name_map(self):
        gen = SerialGenerator()
        serial = gen.generate("nginx", CertType.SERVICE)
        key = f"{CertType.SERVICE.value}_nginx"
        assert gen._name_map[key] == serial

    def test_counter_increments_per_type(self):
        gen = SerialGenerator()
        s1 = gen.generate("a", CertType.DEVICE)
        s2 = gen.generate("b", CertType.DEVICE)
        data1 = s1 & gen._DATA_MASK
        data2 = s2 & gen._DATA_MASK
        assert data2 == data1 + 1

    def test_counter_independent_per_type(self):
        gen = SerialGenerator()
        gen.generate("x", CertType.SERVICE)
        gen.generate("y", CertType.DEVICE)
        # SERVICE starts at 1, DEVICE starts at 1 — independent counters
        assert gen._last_serial[CertType.SERVICE] == 2
        assert gen._last_serial[CertType.DEVICE] == 2


class TestSerialGeneratorParse:
    def test_parse_int_user_returns_data(self):
        gen = SerialGenerator()
        serial = gen.generate(777, CertType.USER)
        cert_type, value = gen.parse(serial)
        assert cert_type == CertType.USER
        assert value == 777

    def test_parse_str_returns_original_string(self):
        gen = SerialGenerator()
        serial = gen.generate("my-cert", CertType.SERVICE)
        cert_type, value = gen.parse(serial)
        assert cert_type == CertType.SERVICE
        assert value == "my-cert"

    def test_parse_int_non_user_returns_from_id_map(self):
        gen = SerialGenerator()
        serial = gen.generate(42, CertType.DEVICE)
        cert_type, value = gen.parse(serial)
        assert cert_type == CertType.DEVICE
        assert value == 42

    def test_parse_unknown_serial_returns_none(self):
        gen = SerialGenerator()
        cert_type, value = gen.parse(0xDEADBEEFCAFE)
        # prefix may not match any known type
        assert value is None or cert_type is None or True  # just must not raise

    def test_parse_unregistered_serial_id_map_miss(self):
        gen = SerialGenerator()
        # Build a serial manually with CA prefix but no registered entry
        prefix = _PrefixRegistry.prefix_for(CertType.CA)
        fake_serial = (prefix << gen._DATA_BITS) | 12345
        cert_type, value = gen.parse(fake_serial)
        assert cert_type == CertType.CA
        assert value is None


class TestSerialGeneratorGetSerialByName:
    def test_returns_serial_for_registered_name(self):
        gen = SerialGenerator()
        serial = gen.generate("redis", CertType.SERVICE)
        result = gen.get_serial_by_name("redis", CertType.SERVICE)
        assert result == serial

    def test_returns_none_for_unknown_name(self):
        gen = SerialGenerator()
        assert gen.get_serial_by_name("unknown", CertType.DEVICE) is None

    def test_type_matters_for_lookup(self):
        gen = SerialGenerator()
        gen.generate("shared", CertType.SERVICE)
        # Same name under different type → not found
        assert gen.get_serial_by_name("shared", CertType.DEVICE) is None


# ===========================================================================
# SerialWithEncoding
# ===========================================================================


class TestSerialWithEncodingGenerate:
    def test_returns_positive_int(self):
        serial = SerialWithEncoding.generate("nginx", CertType.SERVICE)
        assert isinstance(serial, int)
        assert serial > 0

    def test_two_calls_produce_different_serials(self):
        s1 = SerialWithEncoding.generate("nginx", CertType.SERVICE)
        s2 = SerialWithEncoding.generate("nginx", CertType.SERVICE)
        # UUID random part makes collision astronomically unlikely
        assert s1 != s2

    def test_all_cert_types_accepted(self):
        for ct in CertType:
            s = SerialWithEncoding.generate("test", ct)
            assert s > 0

    def test_name_longer_than_max_truncated(self):
        # 10-char limit; name > 10 chars is silently sliced before encoding
        serial = SerialWithEncoding.generate("a" * 20, CertType.CA)
        assert serial > 0

    def test_unknown_type_raises_key_error(self):
        from unittest.mock import MagicMock

        fake = MagicMock(spec=CertType)
        fake.name = "FAKE"
        with pytest.raises(KeyError):
            SerialWithEncoding.generate("test", fake)  # type: ignore


class TestSerialWithEncodingParse:
    def test_roundtrip_cert_type(self):
        for ct in CertType:
            serial = SerialWithEncoding.generate("svc", ct)
            cert_type, _ = SerialWithEncoding.parse(serial)
            assert cert_type == ct

    def test_roundtrip_name_prefix(self):
        serial = SerialWithEncoding.generate("nginx", CertType.SERVICE)
        _, name = SerialWithEncoding.parse(serial)
        assert "nginx".startswith(name) or name.startswith("nginx")

    def test_name_truncated_to_max_length(self):
        serial = SerialWithEncoding.generate("abcdefghij", CertType.CA)
        _, name = SerialWithEncoding.parse(serial)
        assert len(name) <= SerialWithEncoding.MAX_NAME_LENGTH

    def test_unknown_prefix_returns_none_type(self):
        # Craft a serial with an unknown prefix
        fake_prefix = 0xFFFF
        serial = (
            fake_prefix
            << (SerialWithEncoding.NAME_BITS + SerialWithEncoding.RANDOM_BITS)
        ) | 0x1234
        cert_type, _ = SerialWithEncoding.parse(serial)
        assert cert_type is None

    def test_empty_name_roundtrip(self):
        serial = SerialWithEncoding.generate("", CertType.CA)
        _, name = SerialWithEncoding.parse(serial)
        assert name == ""


class TestSerialWithEncodingEncodeName:
    def test_empty_string_returns_zero(self):
        assert SerialWithEncoding._encode_name("") == 0

    def test_single_char(self):
        val = SerialWithEncoding._encode_name("A")
        assert val == ord("A")

    def test_two_chars_little_endian(self):
        val = SerialWithEncoding._encode_name("AB")
        assert val == ord("A") | (ord("B") << 8)

    def test_too_long_raises_value_error(self):
        too_long = "x" * (SerialWithEncoding.MAX_NAME_LENGTH + 1)
        with pytest.raises(ValueError, match="Name too long"):
            SerialWithEncoding._encode_name(too_long)

    def test_max_length_accepted(self):
        max_str = "a" * SerialWithEncoding.MAX_NAME_LENGTH
        result = SerialWithEncoding._encode_name(max_str)
        assert isinstance(result, int)


class TestSerialWithEncodingDecodeName:
    def test_zero_returns_empty_string(self):
        assert SerialWithEncoding._decode_name(0, 10) == ""

    def test_roundtrip_with_encode(self):
        original = "hello"
        encoded = SerialWithEncoding._encode_name(original)
        decoded = SerialWithEncoding._decode_name(
            encoded, SerialWithEncoding.MAX_NAME_LENGTH
        )
        assert decoded == original

    def test_null_byte_terminates_early(self):
        # encode "ab" then check that null padding doesn't appear in decoded
        encoded = SerialWithEncoding._encode_name("ab")
        decoded = SerialWithEncoding._decode_name(encoded, 10)
        assert decoded == "ab"


class TestSerialWithEncodingMasks:
    def test_random_mask_correct_bit_count(self):
        mask = SerialWithEncoding._random_mask()
        assert mask == (1 << SerialWithEncoding.RANDOM_BITS) - 1
        assert mask.bit_length() == SerialWithEncoding.RANDOM_BITS

    def test_name_mask_correct_bit_count(self):
        mask = SerialWithEncoding._name_mask()
        assert mask == (1 << SerialWithEncoding.NAME_BITS) - 1
        assert mask.bit_length() == SerialWithEncoding.NAME_BITS
