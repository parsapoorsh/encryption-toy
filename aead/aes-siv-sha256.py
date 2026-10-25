"""
impersonation of AES-GCM-SIV with SHA256
"""

import os
import hmac
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# RFC 8452 S6: P_MAX = A_MAX = 2^36 octets; N_MIN = N_MAX = 12.
# CTR with high-bit clear could go far higher; GCM-SIV caps here.
MAX_PLAINTEXT_BYTES = 1 << 36  # 64 GiB
MAX_AD_BYTES = 1 << 36  # 64 GiB
MAX_NONCE_BYTES = 12
TAG_SIZE = 16
KEY_SIZE = 16


def ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    if KEY_SIZE == 16:
        algo = algorithms.AES128
    elif KEY_SIZE == 32:
        algo = algorithms.AES256
    else:
        raise ValueError("key must be 16 or 32 bytes")

    enc = Cipher(algo(key), modes.CTR(nonce)).encryptor()
    return enc.update(data) + enc.finalize()


def compute_tag(
    k_tag: bytes,
    plain_text: bytes,
    associated_data: bytes,
    nonce: bytes,
):
    ad_bit_count = len(associated_data) * 8
    pt_bit_count = len(plain_text) * 8

    # RFC 8452 length block: bit-lengths of AD and PT, each 8 bytes little-endian.
    message = (
        pt_bit_count.to_bytes(8, "little") +
        ad_bit_count.to_bytes(8, "little") +
        plain_text +
        associated_data +
        nonce
    )
    tag = hmac.new(k_tag, message, sha256).digest()
    return tag[:TAG_SIZE]


def get_ctr_nonce(tag: bytes):
    # RFC 8452: clear the high bit of the tag before using it as CTR nonce
    # to stop wrapping of CTR nonce
    if len(tag) < 16:
        raise ValueError("tag must be at least 16 bytes")
    ctr_nonce = bytearray(tag[:16])
    ctr_nonce[0] &= 0x7F
    ctr_nonce = bytes(ctr_nonce)
    return ctr_nonce


def check_sizes(
    k_tag: bytes,
    k_enc: bytes,
    text: bytes,
    associated_data: bytes,
    nonce: bytes,
):
    if len(k_tag) != KEY_SIZE or len(k_enc) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(text) > MAX_PLAINTEXT_BYTES:
        raise ValueError("plain/cipher text too long")
    if len(associated_data) > MAX_AD_BYTES:
        raise ValueError("associated data too long")
    if len(nonce) != MAX_NONCE_BYTES:
        raise ValueError(f"nonce must be {MAX_NONCE_BYTES} bytes")


def encrypt_aead(
    k_tag: bytes,
    k_enc: bytes,
    plain_text: bytes,
    associated_data: bytes,
    nonce: bytes,
) -> tuple[bytes, bytes]:
    check_sizes(
        k_tag,
        k_enc,
        plain_text,
        associated_data,
        nonce,
    )

    # tag-then-encrypt; tag is the synthetic IV
    tag = compute_tag(
        k_tag,
        plain_text,
        associated_data,
        nonce,
    )
    ctr_nonce = get_ctr_nonce(tag)
    cipher_text = ctr_crypt(k_enc, ctr_nonce, plain_text)

    return cipher_text, tag


def decrypt_aead(
    k_tag: bytes,
    k_enc: bytes,
    cipher_text: bytes,
    tag: bytes,
    associated_data: bytes,
    nonce: bytes,
) -> bytes:
    check_sizes(
        k_tag,
        k_enc,
        cipher_text,
        associated_data,
        nonce,
    )
    if len(tag) != TAG_SIZE:
        raise ValueError("invalid tag size")

    ctr_nonce = get_ctr_nonce(tag)
    plain_text = ctr_crypt(k_enc, ctr_nonce, cipher_text)
    computed_tag = compute_tag(
        k_tag,
        plain_text,
        associated_data,
        nonce,
    )

    if not hmac.compare_digest(tag, computed_tag):
        raise ValueError("Invalid tag / Authentication failed")

    return plain_text


if __name__ == "__main__":
    KEY_TAG = os.urandom(KEY_SIZE)
    KEY_ENC = os.urandom(KEY_SIZE)

    print("================== deterministic ==================")
    print("Key TAG         :", KEY_TAG.hex())
    print("Key Encryption  :", KEY_ENC.hex())
    print()

    plain_text = b"\x00" * 3
    associated_data = b"\xFF" * 6
    nonce = b"\x00" * 12

    print("Plain Text      :", plain_text.hex())
    print("Associated Data :", associated_data.hex())
    cipher_text, tag = encrypt_aead(KEY_TAG, KEY_ENC, plain_text, associated_data, nonce)
    print("Cipher Text     :", cipher_text.hex())
    print("TAG             :", tag.hex())
    print()

    pt2 = decrypt_aead(KEY_TAG, KEY_ENC, cipher_text, tag, associated_data, nonce)
    assert pt2 == plain_text

    # deterministic: same inputs -> same tag
    ct2, t2 = encrypt_aead(KEY_TAG, KEY_ENC, plain_text, associated_data, nonce)
    assert tag == t2 and cipher_text == ct2

    # no equality leak: different meta data -> different tag
    ad3 = b"different"
    ct3, t3 = encrypt_aead(KEY_TAG, KEY_ENC, plain_text, ad3, nonce)
    assert tag != t3 and cipher_text != ct3
    print("EAssociated Data:", ad3.hex())
    print("ECipher Text    :", ct3.hex())
    print("ETAG            :", t3.hex())
    print()

    # tamper check
    try:
        decrypt_aead(KEY_TAG, KEY_ENC, cipher_text, tag, b"tampered", nonce)
        raise SystemExit("tamper check failed")
    except ValueError:
        print("tamper reject   : ok")
