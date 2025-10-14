# Chain-of-Through secure implementation for AES-CBC encryption.
# 1) Problem understanding: Encrypt a provided key using AES-CBC and return Base64(IV||ciphertext).
# 2) Security requirements: Use a fresh random IV, validate key lengths, apply PKCS7 padding.
# 3) Secure coding generation: Use PyCryptodome AES with CBC mode, strong randomness.
# 4) Code review: Validate inputs and sizes; return combined IV+ciphertext.
# 5) Secure code output: Provide test cases.

from typing import ByteString
from base64 import b64encode

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad
except Exception as e:
    # If PyCryptodome is not available, this module will not run; the function is defined as required.
    pass

def encrypt_key(aes_key: ByteString, key_to_encrypt: ByteString) -> str:
    if aes_key is None or key_to_encrypt is None:
        raise ValueError("Inputs must not be None")
    if len(aes_key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    iv = get_random_bytes(16)
    cipher = AES.new(bytes(aes_key), AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(bytes(key_to_encrypt), AES.block_size))
    return b64encode(iv + ct).decode("utf-8")

if __name__ == "__main__":
    # 5 test cases
    k128 = bytes.fromhex("00112233445566778899aabbccddeeff")
    k192 = bytes.fromhex("00112233445566778899aabbccddeeff0011223344556677")
    k256 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

    print("Test1:", encrypt_key(k128, b"secret-key-1"))
    print("Test2:", encrypt_key(k192, b"another-secret-key-2"))
    print("Test3:", encrypt_key(k256, b"K3"))
    print("Test4:", encrypt_key(k128, bytes([0x00, 0x01, 0x02, 0x03, 0xFF])))
    print("Test5:", encrypt_key(k256, b"A much longer piece of data to encrypt as key material."))