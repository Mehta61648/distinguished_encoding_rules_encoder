import datetime
import unittest

from distinguished_encoding_rules_encoder import (
    DEREncoder,
    der_bit_string,
    der_boolean,
    der_context,
    der_generalized_time,
    der_ia5_string,
    der_integer,
    der_null,
    der_octet_string,
    der_oid,
    der_printable_string,
    der_sequence,
    der_set,
    der_utc_time,
    der_utf8_string,
)


class TestLength(unittest.TestCase):
    def test_short_form(self):
        # value of 5 -> length byte 0x05
        self.assertEqual(der_null(), b"\x05\x00")

    def test_long_form_128(self):
        # exactly 128 content bytes triggers long form: 0x81 0x80
        data = b"\x00" * 128
        enc = der_octet_string(data)
        self.assertEqual(enc[0], 0x04)
        self.assertEqual(enc[1:3], b"\x81\x80")
        self.assertEqual(enc[3:], data)

    def test_long_form_256(self):
        data = b"\x41" * 256
        enc = der_octet_string(data)
        self.assertEqual(enc[1:4], b"\x82\x01\x00")


class TestBoolean(unittest.TestCase):
    def test_true(self):
        self.assertEqual(der_boolean(True), b"\x01\x01\xff")

    def test_false(self):
        self.assertEqual(der_boolean(False), b"\x01\x01\x00")


class TestInteger(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(der_integer(0), b"\x02\x01\x00")

    def test_small_positive(self):
        self.assertEqual(der_integer(5), b"\x02\x01\x05")

    def test_127(self):
        self.assertEqual(der_integer(127), b"\x02\x01\x7f")

    def test_128_requires_leading_zero(self):
        # top bit set -> must prefix 0x00 so it stays positive
        self.assertEqual(der_integer(128), b"\x02\x02\x00\x80")

    def test_256(self):
        self.assertEqual(der_integer(256), b"\x02\x02\x01\x00")

    def test_negative_one(self):
        self.assertEqual(der_integer(-1), b"\x02\x01\xff")

    def test_negative_128(self):
        # -128 in two's complement is 0x80, but top bit set means negative, so no prefix
        self.assertEqual(der_integer(-128), b"\x02\x01\x80")

    def test_negative_129(self):
        # -129 needs 0xFF 0x7F
        self.assertEqual(der_integer(-129), b"\x02\x02\xff\x7f")


class TestOctetString(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(der_octet_string(b""), b"\x04\x00")

    def test_bytes(self):
        self.assertEqual(der_octet_string(b"abc"), b"\x04\x03abc")

    def test_bytearray_accepted(self):
        self.assertEqual(der_octet_string(bytearray(b"xy")), b"\x04\x02xy")

    def test_rejects_str(self):
        with self.assertRaises(TypeError):
            der_octet_string("not bytes")


class TestBitString(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(der_bit_string(b""), b"\x03\x01\x00")

    def test_with_unused_bits(self):
        self.assertEqual(der_bit_string(b"\xff", unused_bits=3), b"\x03\x02\x03\xff")

    def test_rejects_bad_unused(self):
        with self.assertRaises(ValueError):
            der_bit_string(b"\x00", unused_bits=8)


class TestNull(unittest.TestCase):
    def test_null(self):
        self.assertEqual(der_null(), b"\x05\x00")


class TestOID(unittest.TestCase):
    def test_rsa_oid(self):
        # 1.2.840.113549.1.1.1 (rsaEncryption)
        self.assertEqual(
            der_oid("1.2.840.113549.1.1.1"),
            b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",
        )

    def test_two_arc_oid(self):
        self.assertEqual(der_oid("1.2"), b"\x06\x01\x2a")

    def test_rejects_bad_arcs(self):
        with self.assertRaises(ValueError):
            der_oid("1.40")
        with self.assertRaises(ValueError):
            der_oid("3.2")


class TestSequence(unittest.TestCase):
    def test_wraps_items(self):
        items = [der_integer(1), der_integer(2)]
        self.assertEqual(der_sequence(items), b"\x30\x06\x02\x01\x01\x02\x01\x02")

    def test_empty(self):
        self.assertEqual(der_sequence([]), b"\x30\x00")


class TestSet(unittest.TestCase):
    def test_sorts_elements(self):
        # deliberately out of DER order
        items = [der_integer(2), der_integer(1)]
        self.assertEqual(der_set(items), b"\x31\x06\x02\x01\x01\x02\x01\x02")


class TestContext(unittest.TestCase):
    def test_explicit_wrapper(self):
        inner = der_octet_string(b"\x00")
        self.assertEqual(der_context(0, inner), b"\xa0\x03\x04\x01\x00")

    def test_rejects_large_tag(self):
        with self.assertRaises(ValueError):
            der_context(31, b"")


class TestStrings(unittest.TestCase):
    def test_utf8(self):
        self.assertEqual(der_utf8_string("AB"), b"\x0c\x02AB")

    def test_utf8_multibyte(self):
        enc = der_utf8_string("\u00e9")
        self.assertEqual(enc, b"\x0c\x02\xc3\xa9")

    def test_printable(self):
        self.assertEqual(der_printable_string("Test-1"), b"\x13\x06Test-1")

    def test_printable_rejects_at(self):
        with self.assertRaises(ValueError):
            der_printable_string("a@b")

    def test_ia5(self):
        self.assertEqual(der_ia5_string("a@b"), b"\x16\x03a@b")

    def test_ia5_rejects_non_ascii(self):
        with self.assertRaises(ValueError):
            der_ia5_string("\u00e9")


class TestTime(unittest.TestCase):
    def test_utc_time(self):
        dt = datetime.datetime(2023, 1, 15, 12, 30, 45, tzinfo=datetime.timezone.utc)
        self.assertEqual(der_utc_time(dt), b"\x17\x0d230115123045Z")

    def test_utc_time_converts_tz(self):
        tz = datetime.timezone(datetime.timedelta(hours=5))
        dt = datetime.datetime(2023, 1, 15, 17, 30, 45, tzinfo=tz)
        # 17:30 +05:00 == 12:30 UTC
        self.assertEqual(der_utc_time(dt), b"\x17\x0d230115123045Z")

    def test_utc_time_rejects_naive(self):
        with self.assertRaises(ValueError):
            der_utc_time(datetime.datetime(2023, 1, 15))

    def test_utc_time_rejects_2050(self):
        with self.assertRaises(ValueError):
            der_utc_time(datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc))

    def test_generalized_time(self):
        dt = datetime.datetime(2050, 1, 15, 12, 30, 45, tzinfo=datetime.timezone.utc)
        self.assertEqual(der_generalized_time(dt), b"\x18\x0f20500115123045Z")

    def test_generalized_time_rejects_naive(self):
        with self.assertRaises(ValueError):
            der_generalized_time(datetime.datetime(2050, 1, 15))


class TestEncoderClass(unittest.TestCase):
    def test_mirrors_functions(self):
        enc = DEREncoder()
        self.assertEqual(enc.integer(5), der_integer(5))
        self.assertEqual(enc.boolean(True), der_boolean(True))
        self.assertEqual(enc.null(), der_null())

    def test_sequence_via_method(self):
        enc = DEREncoder()
        items = [enc.integer(1), enc.integer(2)]
        self.assertEqual(enc.sequence(items), der_sequence(items))


if __name__ == "__main__":
    unittest.main()
