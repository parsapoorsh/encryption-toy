from time import time
from hashlib import sha1
from hmac import new as hmac_new
from base64 import b32decode


WINDOW = 30  # seconds
DIGIT_COUNT = 6
KEY_B32 = "63KXPJTR5WYS4QCHTATSL6LL4M======"


def dynamic_truncate(digest: bytes) -> int:
    offset = digest[-1] & 0x0F
    truncated = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return truncated


def get_otp(secret: bytes, index: int, digit_count: int) -> int:
    counter = index.to_bytes(8, "big")
    digest = hmac_new(secret, counter, sha1).digest()
    truncated = dynamic_truncate(digest)
    divisor = 10 ** digit_count
    otp_code = truncated % divisor
    return otp_code


timestamp = time()
index = int(timestamp / WINDOW)
ttl = WINDOW - (timestamp % WINDOW)

otp_code = get_otp(b32decode(KEY_B32), index, DIGIT_COUNT)

print()
print("-" * 32)
print("OTP (RFC 6238 TOTP)")
print("-" * 32)
print("timestamp:", f"{timestamp:.2f}")
print("index    :", index)
print("window   :", f"{WINDOW}s")
print("key b32  :", KEY_B32)
print("otp      :", f"{otp_code:0{DIGIT_COUNT}d}")
print("valid for:", f"{ttl:.2f}s")
print("-" * 32)
print()
