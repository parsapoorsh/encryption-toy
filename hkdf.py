#!/usr/bin/env python3

import hashlib
import hmac

# nb: unused here; but SHA512/256 in extract phase provides stronger
# extraction guarantees when expand is SHA256.
# hash_function_extract = hashlib.sha512
# RFC5869 includes SHA-1 test vectors
hash_function = hashlib.sha256


def hmac_digest(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hash_function).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if len(salt) == 0:
        salt = bytes([0] * hash_function().digest_size)
    return hmac_digest(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t = b""
    okm = b""
    i = 0
    while len(okm) < length:
        i += 1
        t = hmac_digest(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


okm = hkdf(
    salt=bytes.fromhex("000102030405060708090a0b0c"),
    ikm=bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
    length=42,
)
assert okm == bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)

# Zero-length salt
assert hkdf(
    salt=b"",
    ikm=bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    info=b"",
    length=42,
) == bytes.fromhex(
    "8da4e775a563c18f715f802a063c5a31"
    "b8a11f5c5ee1879ec3454e5f3c738d2d"
    "9d201395faa4b61a96c8"
)
