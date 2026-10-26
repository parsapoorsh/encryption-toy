"""
Fast-key-erasure RNG (AES-256) — Bernstein, 2017.

https://blog.cr.yp.to/20170723-random.html

Starting from a 256-bit key k, generate 48 blocks:

  B0 = AES_k(0), B1 = AES_k(1), ..., B47 = AES_k(47)

Immediately overwrite k with B0 || B1.
Use B2 ... B47 as 736 bytes of RNG output, erasing each byte
as soon as it is consumed. Start over with the new key.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEYLEN = 32
BLOCKLEN = 16
N_BLOCKS = 48
OUTLEN = (N_BLOCKS - 2) * BLOCKLEN  # 736


def wipe(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


class FastKeyErasureRNG:
    """AES-256 fast-key-erasure RNG. key must be 32 uniform random bytes."""

    def __init__(self, key: bytes) -> None:
        if len(key) != KEYLEN:
            raise ValueError(f"key must be {KEYLEN} bytes")
        self.key = bytearray(key)
        self.buf = bytearray()
        self.pos = 0

    def refill(self) -> None:
        # B0...B47 = AES_k(0)...AES_k(47) via AES-256-CTR with zero IV
        encryptor = Cipher(
            algorithms.AES(bytes(self.key)),
            modes.CTR(b"\x00" * BLOCKLEN),
        ).encryptor()
        stream = bytearray(
            encryptor.update(b"\x00" * (N_BLOCKS * BLOCKLEN))
            + encryptor.finalize()
        )

        wipe(self.key)
        self.key[:] = stream[:KEYLEN]

        wipe(self.buf)
        self.buf = bytearray(stream[KEYLEN:])
        self.pos = 0

        wipe(stream)

    def generate(self, n: int) -> bytes:
        if n < 1:
            raise ValueError("n must be >= 1")

        out = bytearray(n)
        filled = 0
        while filled < n:
            if self.pos >= len(self.buf):
                self.refill()
            take = min(n - filled, len(self.buf) - self.pos)
            out[filled:filled + take] = self.buf[self.pos:self.pos + take]
            for i in range(self.pos, self.pos + take):
                self.buf[i] = 0
            self.pos += take
            filled += take
        return bytes(out)
