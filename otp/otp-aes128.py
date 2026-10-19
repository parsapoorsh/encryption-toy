from time import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


WINDOW = 30  # seconds
DIGIT_COUNT = 6
KEY = bytes.fromhex("f6d577a671edb12e4047982725f96be3")


def get_otp(secret: bytes, index: int, digit_count: int) -> int:
    data = secret + index.to_bytes(16, "big")

    enc = Cipher(algorithms.AES128(key=secret), modes.ECB()).encryptor()
    cipher_text = enc.update(data=data) + enc.finalize()

    divisor = 10 ** digit_count
    otp_code = int.from_bytes(cipher_text, "big") % divisor
    return otp_code


timestamp = time()
index = int(timestamp / WINDOW)
ttl = WINDOW - (timestamp % WINDOW)

otp_code = get_otp(KEY, index, DIGIT_COUNT)

print()
print("-" * 32)
print("OTP")
print("-" * 32)
print("timestamp:", f"{timestamp:.2f}")
print("index    :", index)
print("window   :", f"{WINDOW}s")
print("key      :", KEY.hex())
print("otp      :", f"{otp_code:0{DIGIT_COUNT}d}")
print("valid for:", f"{ttl:.2f}s")
print("-" * 32)
print()
