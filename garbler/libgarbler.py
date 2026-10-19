"""
An encryption/decryption lib that Garbles
the entire data if even a single bit is flipped
"""

from hashlib import sha256

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def ctr_toggle(key: bytes, nonce: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES256(key), modes.CTR(nonce)).encryptor()
    return enc.update(data) + enc.finalize()


def encrypt(key1: bytes, key2: bytes, nonce: bytes, plain_text: bytes) -> bytes:
    # intermediate = CTR(key1, nonce, p)
    # head || tail = intermediate
    #
    # lock(key, seed, data) = ECB_E(key2, ECB_E(HASH(seed), data))
    #
    # tail = lock(key2, head, tail) # 1
    # head = lock(key2, tail, head) # 2
    # tail = lock(key2, head, tail) # 3
    #
    # cipher-text = head || tail

    def lock(key2: bytes, seed: bytes, data: bytes) -> bytes:
        def ecb_encrypt(key: bytes, data: bytes) -> bytes:
            enc = Cipher(algorithms.AES256(key), modes.ECB()).encryptor()
            return enc.update(data) + enc.finalize()

        h = sha256(seed).digest()
        return ecb_encrypt(key2, ecb_encrypt(h, data))

    intermediate = ctr_toggle(key1, nonce, plain_text)

    mid = len(intermediate) // 2
    head = intermediate[:mid]
    tail = intermediate[mid:]

    tail = lock(key2, head, tail)  # 1
    head = lock(key2, tail, head)  # 2
    tail = lock(key2, head, tail)  # 3

    cipher_text = head + tail
    return cipher_text


def decrypt(key1: bytes, key2: bytes, nonce: bytes, cipher_text: bytes) -> bytes:
    # head || tail = cipher-text
    #
    # unlock(key, seed, data) = ECB_D(HASH(seed), ECB_D(key2, data))
    #
    # tail = unlock(key2, head, tail)   # undo 3
    # head = unlock(key2, tail, head)   # undo 2
    # tail = unlock(key2, head, tail)   # undo 1
    #
    # plain-text = CTR(key1, nonce, head || tail)

    def unlock(key2: bytes, seed: bytes, data: bytes) -> bytes:
        # reverse of lock
        def ecb_decrypt(key: bytes, data: bytes) -> bytes:
            dec = Cipher(algorithms.AES256(key), modes.ECB()).decryptor()
            return dec.update(data) + dec.finalize()

        h = sha256(seed).digest()
        return ecb_decrypt(h, ecb_decrypt(key2, data))

    mid = len(cipher_text) // 2
    head = cipher_text[:mid]
    tail = cipher_text[mid:]

    tail = unlock(key2, head, tail)  # undo 3
    head = unlock(key2, tail, head)  # undo 2
    tail = unlock(key2, head, tail)  # undo 1

    intermediate = head + tail
    plain_text = ctr_toggle(key1, nonce, intermediate)
    return plain_text
