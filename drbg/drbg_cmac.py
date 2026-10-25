"""
CMAC_DRBG - HMAC_DRBG construction (NIST SP 800-90A Rev. 1 Section 10.1.2)
with AES-128 CMAC in place of HMAC-SHA-256.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC


MAX_BYTES_PER_REQUEST = 1 << 16  # 2^19 bits
RESEED_INTERVAL = 1 << 48

# Instantiation minima for security_strength = 128 (Tables 2-3, Section 8.6.7).
MIN_ENTROPY_BYTES = 16  # security_strength bits
MIN_NONCE_BYTES = 8     # security_strength / 2 bits (when nonce is random)

# AES-128 block / CMAC tag length
OUTLEN = 16  # 128 bits


def cmac(key: bytes, data: bytes) -> bytes:
    """AES-128 CMAC(key, data) -> 16-byte tag."""
    c = CMAC(algorithms.AES128(key))
    c.update(data)
    return c.finalize()


class CMACDRBG:
    """HMAC_DRBG-style DRBG with AES-128 CMAC."""

    def __init__(self, entropy: bytes, nonce: bytes) -> None:
        # NIST HMAC_DRBG_Instantiate_algorithm (Section 10.1.2.3), CMAC variant
        if len(entropy) < MIN_ENTROPY_BYTES:
            raise ValueError(
                f"entropy must be at least {MIN_ENTROPY_BYTES} bytes"
            )
        if len(nonce) < MIN_NONCE_BYTES:
            raise ValueError(
                f"nonce must be at least {MIN_NONCE_BYTES} bytes"
            )
        self.reseed_counter = 1
        # seed_material = entropy_input || nonce || personalization_string
        self.key = b"\x00" * OUTLEN
        self.value = b"\x01" * OUTLEN
        self.update(entropy + nonce)

    def update(self, provided_data: bytes) -> None:
        """HMAC_DRBG_Update (Section 10.1.2.2), CMAC variant."""
        key = self.key
        value = self.value

        key = cmac(key, value + b"\x00" + provided_data)
        value = cmac(key, value)
        # provided_data = Null -> return after steps 1-2
        if provided_data:
            key = cmac(key, value + b"\x01" + provided_data)
            value = cmac(key, value)

        self.key = key
        self.value = value

    def reseed(self, entropy: bytes) -> None:
        # HMAC_DRBG_Reseed_algorithm (Section 10.1.2.4), CMAC variant
        # seed_material = entropy_input || additional_input
        self.update(entropy)
        self.reseed_counter = 1

    def generate(self, n: int) -> bytes:
        # HMAC_DRBG_Generate_algorithm (Section 10.1.2.5), CMAC variant
        if n < 1:
            raise ValueError("n must be >= 1")
        if n > MAX_BYTES_PER_REQUEST:
            raise ValueError("n exceeds max bytes per request")
        if self.reseed_counter > RESEED_INTERVAL:
            raise RuntimeError("reseed required")

        temp = bytearray()
        while len(temp) < n:
            self.value = cmac(self.key, self.value)
            temp.extend(self.value)

        result = bytes(temp[:n])
        # additional_input is Null
        self.update(b"")
        self.reseed_counter += 1
        return result
