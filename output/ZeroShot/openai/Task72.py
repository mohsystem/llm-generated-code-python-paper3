import base64
from typing import ByteString

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
except Exception:
    # Required package not available
    # pip install cryptography
    raise

STATIC_IV = bytes([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
BLOCK_SIZE = 16

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if block_size <= 0:
        raise ValueError("Invalid block size")
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()

def encrypt(key: ByteString, data: ByteString) -> bytes:
    if key is None or data is None:
        raise ValueError("Key/data is None")
    key = bytes(key)
    data = bytes(data)
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key length must be 16, 24, or 32 bytes")
    padded = pkcs7_pad(data, BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(STATIC_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

if __name__ == "__main__":
    key = b"0123456789ABCDEF"  # 16-byte key
    tests = [
        b"",
        b"Hello, World!",
        b"The quick brown fox jumps over the lazy dog",
        b"1234567890abcdef",
        b"A longer message that will span multiple blocks to test padding and encryption correctness."
    ]
    for i, msg in enumerate(tests, 1):
        ct = encrypt(key, msg)
        print(f"Test {i}: {_b64(ct)}")