"""
Common helpers and base class for NIST SP 800-90A Rev. 1 DRBGs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


MAX_BYTES_PER_REQUEST = 1 << 16  # 2^19 bits
RESEED_INTERVAL = 1 << 48

# Instantiation minima for security_strength = 128 (Tables 2-3, §8.6.7).
MIN_ENTROPY_BYTES = 16  # security_strength bits
MIN_NONCE_BYTES = 8     # security_strength / 2 bits (when nonce is random)


def add_mod(value: bytes, addend: int) -> bytes:
    n_bits = len(value) * 8
    result = (int.from_bytes(value, "big") + addend) % (1 << n_bits)
    return result.to_bytes(len(value), "big")


class DRBG(ABC):
    """
    __init__(entropy, nonce)  == NIST Instantiate
    generate(n)               == NIST Generate (n pseudorandom bytes)
    reseed(entropy)           == NIST Reseed

    HMAC_DRBG and CTR_DRBG also expose update() (NIST internal Update).
    Hash_DRBG has no Update function in the standard.
    """

    def __init__(self, entropy: bytes, nonce: bytes) -> None:
        if len(entropy) < MIN_ENTROPY_BYTES:
            raise ValueError(
                f"entropy must be at least {MIN_ENTROPY_BYTES} bytes"
            )
        if len(nonce) < MIN_NONCE_BYTES:
            raise ValueError(
                f"nonce must be at least {MIN_NONCE_BYTES} bytes"
            )
        self.reseed_counter = 1

    @abstractmethod
    def reseed(self, entropy: bytes) -> None:
        ...

    @abstractmethod
    def generate(self, n: int) -> bytes:
        """Return n pseudorandom bytes (like os.urandom)."""
        ...
