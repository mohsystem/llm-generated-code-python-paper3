# python
# WARNING: Using a static IV is insecure and only for demonstration/testing.
from Crypto.Cipher import AES
import base64

STATIC_IV = b"0123456789ABCDEF"


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    padding = block_size - (len(data) % block_size)
    if padding == 0:
        padding = block_size
    return data + bytes([padding]) * padding


def encrypt(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, STATIC_IV)
    padded = pad_pkcs7(data, 16)
    return cipher.encrypt(padded)


def _to_hex(b: bytes) -> str:
    return "".join(f"{x:02x}" for x in b)


if __name__ == "__main__":
    key = b"ThisIsA16ByteKey"  # 16-byte key (AES-128)
    tests = [
        b"",
        b"Hello, AES-CBC!",
        b"The quick brown fox jumps over the lazy dog",
        b"1234567890ABCDEF1234",
        b"Data with \x00 nulls \x00 inside",
    ]
    for i, t in enumerate(tests, 1):
        ct = encrypt(key, t)
        print(f"Test {i} Base64: {base64.b64encode(ct).decode('utf-8')}")
        print(f"Test {i} Hex:    {_to_hex(ct)}")