"""
An encryption/decryption tool that Garbles
the entire data if even a single bit is flipped
"""

import os

from libgarbler import decrypt, encrypt
from printer import BLOCK_SIZE, block_brackets, print_hex

key1 = os.urandom(32)
key2 = os.urandom(32)
nonce = os.urandom(16)

N_BLOCKS = 6

# which ciphertext block to flip (1 ... N_BLOCKS)
FLIP_BLOCK = 4

print("================== pre-shared ==================")
print("key1  :", key1.hex())
print("key2  :", key2.hex())
print("nonce :", nonce.hex())
print(f"FLIP BLOCK : {FLIP_BLOCK}")
print()

plain_text = b"\x00" * (BLOCK_SIZE * N_BLOCKS)
print(f"              {block_brackets(N_BLOCKS)}")
print_hex("Original  PT: ", plain_text)

cipher_text = encrypt(key1, key2, nonce, plain_text)
print_hex("Encrypted PT: ", cipher_text)

out = decrypt(key1, key2, nonce, cipher_text)
print_hex("Decrypted CT: ", out)
assert out == plain_text

# flip middle byte of FLIP_BLOCK (1-based)
flip_byte = (FLIP_BLOCK - 1) * BLOCK_SIZE + (BLOCK_SIZE // 2)
bit_mask = 0x11

c_list = bytearray(cipher_text)
c_list[flip_byte] ^= bit_mask
c_flipped = bytes(c_list)
print_hex("Flipped   CT: ", c_flipped)

out_flipped = decrypt(key1, key2, nonce, c_flipped)
print_hex("Garbled   PT: ", out_flipped, mark_byte=flip_byte)
