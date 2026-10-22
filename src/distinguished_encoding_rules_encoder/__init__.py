# distinguished_encoding_rules_encoder
"""Encode Python objects into ASN.1 DER bytes.

Public surface:
    DEREncoder          -- stateful encoder producing a single DER structure
    der_boolean         -- encode True/False into a DER BOOLEAN
    der_integer         -- encode an int into a DER INTEGER
    der_octet_string    -- encode bytes into a DER OCTET STRING
    der_bit_string      -- encode bytes into a DER BIT STRING (whole bytes, zero unused bits)
    der_null            -- the DER NULL value (empty V)
    der_oid             -- encode a dotted OID string into a DER OBJECT IDENTIFIER
    der_sequence        -- wrap a list of already-encoded DER items in a DER SEQUENCE
    der_set             -- wrap a list of already-encoded DER items in a DER SET
    der_context         -- wrap already-encoded bytes in a context-specific tag
    der_utf8_string     -- encode a str into a DER UTF8String
    der_printable_string -- encode a str into a DER PrintableString
    der_ia5_string      -- encode a str into a DER IA5String
    der_utc_time        -- encode a datetime (UTCTime, YYMMDDHHMMSSZ)
    der_generalized_time -- encode a datetime (GeneralizedTime, YYYYMMDDHHMMSSZ)

The high-level entry point DEREncoder mirrors this list as instance methods.
"""

from .core import (
    DEREncoder,
    der_boolean,
    der_integer,
    der_octet_string,
    der_bit_string,
    der_null,
    der_oid,
    der_sequence,
    der_set,
    der_context,
    der_utf8_string,
    der_printable_string,
    der_ia5_string,
    der_utc_time,
    der_generalized_time,
)

__all__ = [
    "DEREncoder",
    "der_boolean",
    "der_integer",
    "der_octet_string",
    "der_bit_string",
    "der_null",
    "der_oid",
    "der_sequence",
    "der_set",
    "der_context",
    "der_utf8_string",
    "der_printable_string",
    "der_ia5_string",
    "der_utc_time",
    "der_generalized_time",
]
