# distinguished_encoding_rules_encoder

Encodes Python objects into ASN.1 DER bytes for X.509 certificate and cryptographic key serialization. Standard library only, no third-party dependencies.

## Usage

```python
from distinguished_encoding_rules_encoder import (
    der_integer, der_oid, der_sequence, der_bit_string, der_null,
)

# Build an RSA public key SubjectPublicKeyInfo by hand.
rsa_oid = der_oid("1.2.840.113549.1.1.1")
alg_id = der_sequence([rsa_oid, der_null()])

# A 2048-bit modulus, as a positive INTEGER (leading 0x00 so the top bit is clear).
modulus = der_integer(0x00C6C0)   # your big int here
exponent = der_integer(65537)
rsa_pub = der_sequence([modulus, exponent])

# BIT STRING wrapping the SEQUENCE, one leading unused-bits byte.
pub_key_bits = der_bit_string(rsa_pub)

subject_public_key_info = der_sequence([alg_id, pub_key_bits])
```

The object-oriented form mirrors every function as a method on `DEREncoder`:
`DEREncoder().integer(5)`, `DEREncoder().sequence([...])`, etc.

## Exported names

`DEREncoder`, `der_boolean`, `der_integer`, `der_octet_string`, `der_bit_string`,
`der_null`, `der_oid`, `der_sequence`, `der_set`, `der_context`,
`der_utf8_string`, `der_printable_string`, `der_ia5_string`, `der_utc_time`,
`der_generalized_time`.

## Why this exists

Hand-assembling X.509 and PKCS#8 structures means emitting a handful of DER
primitives -- INTEGER, OID, SEQUENCE, BIT STRING, NULL, context tags -- and
getting the sign-bit padding, length encoding, and OID base-128 packing exactly
right. This library covers exactly those primitives and nothing else. It does
not parse DER, and it does not validate that a constructed structure is
semantically correct ASN.1; it only guarantees that each emitted TLV is valid
DER for its primitive.

The trade-off: you build sequences by passing already-encoded bytes, not by
describing a schema. That is more verbose but keeps the library tiny and the
behaviour transparent -- every function maps one Python object to one DER TLV.

## Edge cases worth knowing

- `der_integer` adds a leading `0x00` when the minimal big-endian representation
  has its top bit set, so positive numbers stay positive; negative numbers get a
  `0xFF` prefix when needed.
- `der_set` sorts its elements by encoded bytes (the "distinguished" rule);
  `der_sequence` preserves caller order.
- `der_utc_time` requires a timezone-aware `datetime` and only accepts years
  1950-2049; outside that range use `der_generalized_time`.
- `der_printable_string` rejects characters outside the X.680 PrintableString
  alphabet (notably `@`); use `der_ia5_string` or `der_utf8_string` instead.
- `der_context` supports tag numbers 0-30 only, which covers every context tag
  in RFC 5280.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

