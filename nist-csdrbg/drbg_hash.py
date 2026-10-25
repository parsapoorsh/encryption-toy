"""
Hash_DRBG - NIST SP 800-90A Rev. 1, Section 10.1.1 (SHA-256).

Hash_DRBG has no separate Update function. Only Instantiate, Reseed, Generate.
"""

from __future__ import annotations

import hashlib

from base import (
    MAX_BYTES_PER_REQUEST,
    RESEED_INTERVAL,
    DRBG,
    add_mod,
)


# Table 2 - SHA-256
OUTLEN = 32          # 256 bits
SEEDLEN = 55         # 440 bits


def hash_df(input_string: bytes, n_bytes: int) -> bytes:
    """Hash_df (Section 10.3.1), returns n_bytes."""
    length = (n_bytes + OUTLEN - 1) // OUTLEN
    temp = bytearray()
    counter = 0x01
    no_of_bits_be = (n_bytes * 8).to_bytes(4, "big")
    for _ in range(length):
        temp.extend(
            hashlib.sha256(
                bytes([counter]) + no_of_bits_be + input_string
            ).digest()
        )
        counter = (counter + 1) & 0xFF
    return bytes(temp[:n_bytes])


class HashDRBG(DRBG):
    """Hash_DRBG with SHA-256."""

    def __init__(self, entropy: bytes, nonce: bytes) -> None:
        # NIST Hash_DRBG_Instantiate_algorithm (Section 10.1.1.2)
        super().__init__(entropy, nonce)
        # seed_material = entropy_input || nonce || personalization_string
        seed = hash_df(entropy + nonce, SEEDLEN)
        self.value = seed
        self.constant = hash_df(b"\x00" + seed, SEEDLEN)

    def reseed(self, entropy: bytes) -> None:
        # Hash_DRBG_Reseed_algorithm (Section 10.1.1.3)
        # seed_material = 0x01 || V || entropy_input || additional_input
        seed_material = b"\x01" + self.value + entropy
        seed = hash_df(seed_material, SEEDLEN)
        self.value = seed
        self.constant = hash_df(b"\x00" + seed, SEEDLEN)
        self.reseed_counter = 1

    def generate(self, n: int) -> bytes:
        # Hash_DRBG_Generate_algorithm (Section 10.1.1.4), no additional_input
        if n < 1:
            raise ValueError("n must be >= 1")
        if n > MAX_BYTES_PER_REQUEST:
            raise ValueError("n exceeds max bytes per request")
        if self.reseed_counter > RESEED_INTERVAL:
            raise RuntimeError("reseed required")

        value = self.value
        block_count = (n + OUTLEN - 1) // OUTLEN
        data = value
        output = bytearray()
        for _ in range(block_count):
            output.extend(hashlib.sha256(data).digest())
            data = add_mod(data, 1)
        result = bytes(output[:n])

        # V = (V + Hash(0x03 || V) + C + reseed_counter) mod 2^seedlen
        digest = hashlib.sha256(b"\x03" + value).digest()
        total = (
            int.from_bytes(digest, "big")
            + int.from_bytes(self.constant, "big")
            + self.reseed_counter
        )
        self.value = add_mod(value, total)
        self.reseed_counter += 1
        return result
