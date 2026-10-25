"""
HMAC_DRBG - NIST SP 800-90A Rev. 1, Section 10.1.2 (HMAC-SHA-256).
"""

from __future__ import annotations

import hashlib
import hmac

from base import (
    MAX_BYTES_PER_REQUEST,
    RESEED_INTERVAL,
    DRBG,
)


# Table 2 - SHA-256
OUTLEN = 32  # 256 bits


class HMACDRBG(DRBG):
    """HMAC_DRBG with SHA-256."""

    def __init__(self, entropy: bytes, nonce: bytes) -> None:
        # NIST HMAC_DRBG_Instantiate_algorithm (Section 10.1.2.3)
        super().__init__(entropy, nonce)
        # seed_material = entropy_input || nonce || personalization_string
        self.key = b"\x00" * OUTLEN
        self.value = b"\x01" * OUTLEN
        self.update(entropy + nonce)

    def update(self, provided_data: bytes) -> None:
        """HMAC_DRBG_Update (Section 10.1.2.2)."""
        key = self.key
        value = self.value

        key = hmac.new(
            key,
            value + b"\x00" + provided_data,
            hashlib.sha256,
        ).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()
        # provided_data = Null -> return after steps 1-2
        if provided_data:
            key = hmac.new(
                key,
                value + b"\x01" + provided_data,
                hashlib.sha256,
            ).digest()
            value = hmac.new(key, value, hashlib.sha256).digest()

        self.key = key
        self.value = value

    def reseed(self, entropy: bytes) -> None:
        # HMAC_DRBG_Reseed_algorithm (Section 10.1.2.4)
        # seed_material = entropy_input || additional_input
        self.update(entropy)
        self.reseed_counter = 1

    def generate(self, n: int) -> bytes:
        # HMAC_DRBG_Generate_algorithm (Section 10.1.2.5), no additional_input
        if n < 1:
            raise ValueError("n must be >= 1")
        if n > MAX_BYTES_PER_REQUEST:
            raise ValueError("n exceeds max bytes per request")
        if self.reseed_counter > RESEED_INTERVAL:
            raise RuntimeError("reseed required")

        temp = bytearray()
        while len(temp) < n:
            self.value = hmac.new(
                self.key,
                self.value,
                hashlib.sha256,
            ).digest()
            temp.extend(self.value)

        result = bytes(temp[:n])
        # additional_input is Null
        self.update(b"")
        self.reseed_counter += 1
        return result
