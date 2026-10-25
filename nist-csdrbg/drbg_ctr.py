"""
CTR_DRBG - NIST SP 800-90A Rev. 1, Section 10.2.1 (AES-128, with df).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from base import (
    MAX_BYTES_PER_REQUEST,
    RESEED_INTERVAL,
    DRBG,
    add_mod,
)


# Table 3 - AES-128
KEYLEN = 16  # 128 bits
BLOCKLEN = 16  # 128 bits
SEEDLEN = KEYLEN + BLOCKLEN  # 256 bits


def block_encrypt(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def block_cipher_chaining(key: bytes, data: bytes) -> bytes:
    """BCC (Section 10.3.3): CBC-style encrypt-chain over outlen blocks."""
    chaining_value = b"\x00" * BLOCKLEN
    for i in range(0, len(data), BLOCKLEN):
        block = data[i:i + BLOCKLEN]
        chaining_value = block_encrypt(
            key,
            bytes(x ^ y for x, y in zip(chaining_value, block)),
        )
    return chaining_value


def block_cipher_derivation_function(input_string: bytes, n_bytes: int) -> bytes:
    """Block_Cipher_df (Section 10.3.2), returns n_bytes."""
    input_len = len(input_string).to_bytes(4, "big")
    output_len = n_bytes.to_bytes(4, "big")
    padded = input_len + output_len + input_string + b"\x80"
    while len(padded) % BLOCKLEN != 0:
        padded += b"\x00"

    # key = leftmost(0x00010203...1D1E1F, keylen)
    key = bytes(range(KEYLEN))

    temp = bytearray()
    index = 0
    while len(temp) < KEYLEN + BLOCKLEN:
        iv = index.to_bytes(4, "big") + b"\x00" * (BLOCKLEN - 4)
        temp.extend(block_cipher_chaining(key, iv + padded))
        index += 1

    key = bytes(temp[:KEYLEN])
    block = bytes(temp[KEYLEN:KEYLEN + BLOCKLEN])

    temp = bytearray()
    while len(temp) < n_bytes:
        block = block_encrypt(key, block)
        temp.extend(block)
    return bytes(temp[:n_bytes])


class CTRDRBG(DRBG):
    """CTR_DRBG with AES-128 and Block_Cipher_df."""

    def __init__(self, entropy: bytes, nonce: bytes) -> None:
        # NIST CTR_DRBG_Instantiate with df (Section 10.2.1.3.2)
        super().__init__(entropy, nonce)
        # seed_material = entropy_input || nonce || personalization_string
        self.key = b"\x00" * KEYLEN
        self.value = b"\x00" * BLOCKLEN
        self.update(block_cipher_derivation_function(entropy + nonce, SEEDLEN))

    def update(self, provided_data: bytes) -> None:
        """CTR_DRBG_Update (Section 10.2.1.2). provided_data must be seedlen bytes."""
        if len(provided_data) != SEEDLEN:
            raise ValueError("provided_data must be seedlen bytes")

        key = self.key
        value = self.value

        temp = bytearray()
        while len(temp) < SEEDLEN:
            value = add_mod(value, 1)
            temp.extend(block_encrypt(key, value))

        temp_bytes = bytes(
            x ^ y for x, y in zip(temp[:SEEDLEN], provided_data)
        )
        self.key = temp_bytes[:KEYLEN]
        self.value = temp_bytes[-BLOCKLEN:]

    def reseed(self, entropy: bytes) -> None:
        # CTR_DRBG_Reseed with df (Section 10.2.1.4.2)
        # seed_material = entropy_input || additional_input
        self.update(block_cipher_derivation_function(entropy, SEEDLEN))
        self.reseed_counter = 1

    def generate(self, n: int) -> bytes:
        # CTR_DRBG_Generate with df (Section 10.2.1.5.2), no additional_input
        if n < 1:
            raise ValueError("n must be >= 1")
        if n > MAX_BYTES_PER_REQUEST:
            raise ValueError("n exceeds max bytes per request")
        if self.reseed_counter > RESEED_INTERVAL:
            raise RuntimeError("reseed required")

        temp = bytearray()
        while len(temp) < n:
            self.value = add_mod(self.value, 1)
            temp.extend(block_encrypt(self.key, self.value))

        result = bytes(temp[:n])
        # additional_input was Null -> provided_data = 0^seedlen
        self.update(b"\x00" * SEEDLEN)
        self.reseed_counter += 1
        return result
