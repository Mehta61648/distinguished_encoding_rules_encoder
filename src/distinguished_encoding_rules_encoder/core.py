"""Core DER encoding primitives.

DER (Distinguished Encoding Rules) is the canonical, non-ambiguous subset of BER
used by X.509 certificates and most cryptographic key formats. Every value has one
and only one valid encoding, which is what makes signatures over DER stable.

This module deliberately implements only the primitives needed to hand-build the
structures found in X.509 and PKCS#8: INTEGER, OCTET STRING, BIT STRING, NULL,
OID, SEQUENCE, SET, context tags, and a handful of string/time types. It does not
parse DER, and it does not validate that a constructed structure is semantically
correct ASN.1 -- it only guarantees that the bytes it emits are valid DER for the
given primitive.
"""

from __future__ import annotations

import datetime

# Universal tag numbers (X.690, 8.1.2.3).
_TAG_BOOLEAN = 0x01
_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_UTF8_STRING = 0x0C
_TAG_SEQUENCE = 0x10
_TAG_SET = 0x11
_TAG_PRINTABLE_STRING = 0x13
_TAG_IA5_STRING = 0x16
_TAG_UTC_TIME = 0x17
_TAG_GENERALIZED_TIME = 0x18

# PrintableString alphabet (RFC 5280, 4.1.2.4 Table 1 and X.680 §41).
_PRINTABLE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 "
    "'()+,-./:=?"
)


def _encode_length(n: int) -> bytes:
    """Encode the length octets per DER (X.690, 8.1.3).

    Short form (n < 128): one byte.
    Long form: 0x80 | num_length_octets followed by the big-endian length.
    The minimal long form is required by DER, so we must not pad.
    """
    if n < 0:
        raise ValueError("length cannot be negative")
    if n < 0x80:
        return bytes((n,))
    out = b""
    while n > 0:
        out = bytes((n & 0xFF,)) + out
        n >>= 8
    # X.690 requires the fewest length octets, so a leading zero would be illegal.
    if len(out) > 0x7F:
        raise ValueError("length too large to encode")
    return bytes((0x80 | len(out),)) + out


def _tlv(tag: int, value: bytes, constructed: bool = False) -> bytes:
    """Assemble a Tag-Length-Value triple.

    Universal primitive tag byte is 0x00 | tag (class=universal, P/C=primitive).
    Universal constructed tag byte is 0x20 | tag (class=universal, P/C=constructed).
    """
    tag_byte = (0x20 if constructed else 0x00) | tag
    return bytes((tag_byte,)) + _encode_length(len(value)) + value


def der_boolean(value: bool) -> bytes:
    """Encode a Python bool as a DER BOOLEAN.

    DER mandates 0xFF for TRUE and 0x00 for FALSE; any other single byte is invalid.
    This differs from BER, which accepts any non-zero byte as TRUE. Because we emit
    DER only, we hardcode the two canonical contents.
    """
    return _tlv(_TAG_BOOLEAN, b"\xff" if value else b"\x00")


def der_integer(value: int) -> bytes:
    """Encode a Python int as a DER INTEGER.

    INTEGER contents are signed two's-complement, big-endian, minimal. The tricky
    part is the sign bit: if the top bit of the minimal representation is set, a
    leading 0x00 is required so the number is not read as negative; conversely a
    negative number whose top bit would otherwise be clear needs a 0xFF prefix.
    """
    if value == 0:
        return _tlv(_TAG_INTEGER, b"\x00")
    if value > 0:
        out = []
        v = value
        while v > 0:
            out.append(v & 0xFF)
            v >>= 8
        out.reverse()
        if out[0] & 0x80:
            out.insert(0, 0x00)
        return _tlv(_TAG_INTEGER, bytes(out))
    # Negative: build absolute value, then flip bits to get two's complement.
    magnitude = -value
    out = []
    while magnitude > 0:
        out.append(magnitude & 0xFF)
        magnitude >>= 8
    out.reverse()
    # Convert magnitude bytes to two's complement of -value: invert then add 1.
    bits = bytearray(out)
    for i in range(len(bits)):
        bits[i] ^= 0xFF
    carry = 1
    for i in range(len(bits) - 1, -1, -1):
        total = bits[i] + carry
        bits[i] = total & 0xFF
        carry = total >> 8
    if carry:
        bits.insert(0, 0xFF)
    if not (bits[0] & 0x80):
        bits.insert(0, 0xFF)
    return _tlv(_TAG_INTEGER, bytes(bits))


def der_octet_string(data: bytes) -> bytes:
    """Encode raw bytes as a DER OCTET STRING."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("der_octet_string requires bytes")
    return _tlv(_TAG_OCTET_STRING, bytes(data))


def der_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    """Encode bytes as a DER BIT STRING.

    The first content octet is the count of unused bits in the final octet.
    X.509 public keys are almost always byte-aligned, so unused_bits=0 is the
    common case. DER requires that if unused_bits > 0, the trailing bits of the
    final octet must be zero; this function trusts the caller for that rule.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("der_bit_string requires bytes")
    if not isinstance(unused_bits, int):
        raise TypeError("unused_bits must be an int")
    if unused_bits < 0 or unused_bits > 7:
        raise ValueError("unused_bits must be in 0..7")
    return _tlv(_TAG_BIT_STRING, bytes((unused_bits,)) + bytes(data))


def der_null() -> bytes:
    """The DER NULL value: tag 0x05, length 0, no contents."""
    return _tlv(_TAG_NULL, b"")


def der_oid(oid: str) -> bytes:
    """Encode a dotted-decimal OID string as a DER OBJECT IDENTIFIER.

    The first two arcs are packed as 40*x + y. Subsequent arcs use base-128 with a
    continuation bit; each arc is encoded minimally. X.509 OIDs like 1.2.840.113549
    are the primary use case.
    """
    if not isinstance(oid, str):
        raise TypeError("der_oid requires a str")
    arcs = oid.split(".")
    if len(arcs) < 2:
        raise ValueError("OID must have at least two arcs")
    try:
        nums = [int(a) for a in arcs]
    except ValueError:
        raise ValueError("OID arcs must be integers")
    for n in nums:
        if n < 0:
            raise ValueError("OID arcs cannot be negative")
    if nums[0] > 2 or (nums[0] < 2 and nums[1] >= 40):
        raise ValueError("first arc must be 0,1,2; second <40 when first <2")
    first = 40 * nums[0] + nums[1]
    out = bytearray()
    # Encode first byte; base-128 for the rest.
    def _enc_arc(n: int) -> None:
        if n == 0:
            out.append(0)
            return
        chunks = []
        while n > 0:
            chunks.append(n & 0x7F)
            n >>= 7
        chunks.reverse()
        for i in range(len(chunks) - 1):
            out.append(0x80 | chunks[i])
        out.append(chunks[-1])
    _enc_arc(first)
    for a in nums[2:]:
        _enc_arc(a)
    return _tlv(_TAG_OID, bytes(out))


def der_sequence(items: list) -> bytes:
    """Wrap already-encoded DER items in a constructed DER SEQUENCE.

    Each item must already be a full DER TLV (bytes). The SEQUENCE is constructed
    (tag 0x30) and its value is the concatenation of the items. DER requires that
    SET elements be sorted by encoding, but SEQUENCE preserves caller order.
    """
    content = b"".join(items)
    return _tlv(_TAG_SEQUENCE, content, constructed=True)


def der_set(items: list) -> bytes:
    """Wrap already-encoded DER items in a constructed DER SET.

    DER mandates that SET elements appear in ascending order of their encoded bytes
    (X.690, 11.5 -- the "distinguished" part). We sort a copy so the caller's list
    is not mutated.
    """
    ordered = sorted(items)
    content = b"".join(ordered)
    return _tlv(_TAG_SET, content, constructed=True)


def der_context(tag: int, value: bytes, constructed: bool = True) -> bytes:
    """Wrap bytes in a context-specific ([n]) tag.

    X.509 uses context tags for optional fields like [0] EXPLICIT wrappers around
    subjectAltName. This library only supports tag numbers 0..30, which covers all
    tags actually appearing in RFC 5280 structures. Multi-byte tags are omitted.
    """
    if not isinstance(tag, int):
        raise TypeError("tag must be int")
    if tag < 0 or tag > 30:
        raise ValueError("context tag must be 0..30")
    tag_byte = 0x80 | (0x20 if constructed else 0x00) | tag
    return bytes((tag_byte,)) + _encode_length(len(value)) + value


def der_utf8_string(s: str) -> bytes:
    """Encode a Python str as a DER UTF8String."""
    if not isinstance(s, str):
        raise TypeError("der_utf8_string requires a str")
    return _tlv(_TAG_UTF8_STRING, s.encode("utf-8"))


def der_printable_string(s: str) -> bytes:
    """Encode a Python str as a DER PrintableString.

    PrintableString is a restricted ASCII subset. We reject anything outside it so
    the output is valid DER; callers who need arbitrary Unicode should use
    der_utf8_string instead.
    """
    if not isinstance(s, str):
        raise TypeError("der_printable_string requires a str")
    for ch in s:
        if ch not in _PRINTABLE_CHARS:
            raise ValueError(f"{ch!r} is not a PrintableString character")
    return _tlv(_TAG_PRINTABLE_STRING, s.encode("ascii"))


def der_ia5_string(s: str) -> bytes:
    """Encode a Python str as a DER IA5String (ASCII)."""
    if not isinstance(s, str):
        raise TypeError("der_ia5_string requires a str")
    try:
        data = s.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("IA5String must be pure ASCII")
    return _tlv(_TAG_IA5_STRING, data)


def der_utc_time(dt: datetime.datetime) -> bytes:
    """Encode a datetime as DER UTCTime (YYMMDDHHMMSSZ).

    UTCTime is used for certificate validity dates through 2049. We require an
    explicit timezone (aware datetime); passing a naive datetime raises to prevent
    silent UTC assumptions. Seconds are always included per DER.
    """
    if dt.tzinfo is None:
        raise ValueError("der_utc_time requires a tz-aware datetime")
    if dt.year < 1950 or dt.year > 2049:
        raise ValueError("UTCTime is only valid for years 1950-2049; use GeneralizedTime")
    utc = dt.astimezone(datetime.timezone.utc)
    stamp = utc.strftime("%y%m%d%H%M%SZ")
    return _tlv(_TAG_UTC_TIME, stamp.encode("ascii"))


def der_generalized_time(dt: datetime.datetime) -> bytes:
    """Encode a datetime as DER GeneralizedTime (YYYYMMDDHHMMSSZ).

    Used for certificate validity dates from 2050 onward and for any timestamp
    outside UTCTime's 1950-2049 range. We require a tz-aware datetime and emit the
    'Z' (UTC) form mandated by DER; fractional seconds are not emitted.
    """
    if dt.tzinfo is None:
        raise ValueError("der_generalized_time requires a tz-aware datetime")
    utc = dt.astimezone(datetime.timezone.utc)
    stamp = utc.strftime("%Y%m%d%H%M%SZ")
    return _tlv(_TAG_GENERALIZED_TIME, stamp.encode("ascii"))


class DEREncoder:
    """Stateful convenience wrapper over the module-level der_* functions.

    Each method delegates to the corresponding function and returns bytes. The class
    exists so callers who prefer an object-oriented style can chain encodings
    without importing each function individually. It holds no mutable state.
    """

    boolean = staticmethod(der_boolean)
    integer = staticmethod(der_integer)
    octet_string = staticmethod(der_octet_string)
    bit_string = staticmethod(der_bit_string)
    null = staticmethod(der_null)
    oid = staticmethod(der_oid)
    sequence = staticmethod(der_sequence)
    set = staticmethod(der_set)
    context = staticmethod(der_context)
    utf8_string = staticmethod(der_utf8_string)
    printable_string = staticmethod(der_printable_string)
    ia5_string = staticmethod(der_ia5_string)
    utc_time = staticmethod(der_utc_time)
    generalized_time = staticmethod(der_generalized_time)
