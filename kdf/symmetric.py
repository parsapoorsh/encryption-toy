import hashlib
from hkdf import hkdf_expand

IKM_LENGTH = 32
OKM_LENGTH = 16
digestmod = hashlib.sha256

ikm = bytes.fromhex("192275e97ae72e31ba70c9df8a3e2cb5747a522f3d23c33af6d857b610e5e528")

okm = hkdf_expand(ikm, b"okm", OKM_LENGTH, digestmod)
ikm = hkdf_expand(ikm, b"chain", IKM_LENGTH, digestmod)
assert okm.hex() == "69ebf868fe0405b50ea079feb5645adb"
assert ikm.hex() == "904301d816d00e834d339630ce0aad43571e726f4bd45d386bea017297a8b0ce"

okm = hkdf_expand(ikm, b"okm", OKM_LENGTH, digestmod)
ikm = hkdf_expand(ikm, b"chain", IKM_LENGTH, digestmod)
assert okm.hex() == "92119a054efd429273579417ca3c6de9"
assert ikm.hex() == "f55f2a90bd347d9fdfea99e59aa9d6c0e400c125982796b031696dba18200ae5"

okm = hkdf_expand(ikm, b"okm", OKM_LENGTH, digestmod)
ikm = hkdf_expand(ikm, b"chain", IKM_LENGTH, digestmod)
assert okm.hex() == "10113d91cfc487d9942ebe3565d3b395"
assert ikm.hex() == "926e0b6c7767a295d465ee6dffed699061dd1d59d04ee1a3841485ccc51f032b"

okm = hkdf_expand(ikm, b"okm", OKM_LENGTH, digestmod)
ikm = hkdf_expand(ikm, b"chain", IKM_LENGTH, digestmod)
assert okm.hex() == "01789f605521329a33815233ff2921f4"
assert ikm.hex() == "f417d585154ee9ec2e78d0a2415ee08bdb9158f182a76ce3163427123fa49da6"

okm = hkdf_expand(ikm, b"okm", OKM_LENGTH, digestmod)
ikm = hkdf_expand(ikm, b"chain", IKM_LENGTH, digestmod)
assert okm.hex() == "ba01ce88b1e032c06f52dca59e4e59cf"
assert ikm.hex() == "7e86ad50eb3f87f18483b01a930551f204a03543c909fb5ef1eed7cd6783d070"
