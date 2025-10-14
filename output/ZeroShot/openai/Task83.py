import os
import sys
import binascii
import hmac
import hashlib
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
except Exception as e:
    # If cryptography is not available, raise a clear error
    print("This program requires the 'cryptography' package.", file=sys.stderr)
    raise

def encrypt_key(enc_key: bytes, mac_key: bytes, key_to_encrypt: bytes) -> bytes:
    if len(enc_key) not in (16, 24, 32):
        raise ValueError("Encryption key must be 16, 24, or 32 bytes.")
    if not mac_key:
        raise ValueError("MAC key must not be empty.")
    if key_to_encrypt is None:
        raise ValueError("Key to encrypt must not be None.")

    iv = os.urandom(16)

    # PKCS7 pad to AES block size (128 bits)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(key_to_encrypt) + padder.finalize()

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return iv + ciphertext + tag

def hex_to_bytes(s: str) -> bytes:
    return binascii.unhexlify(s.encode())

def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def main():
    enc_key_hex = "603deb1015ca71be2b73aef0857d7781f352c073b6108d72d9810a30914dff4"
    mac_key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    enc_key = hex_to_bytes(enc_key_hex)
    mac_key = hex_to_bytes(mac_key_hex)

    test_keys_hex = [
        "00112233445566778899aabbccddeeff",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "deadbeef",
        "aabbccddeeff",
    ]

    for i, t in enumerate(test_keys_hex, 1):
        pt = hex_to_bytes(t)
        ct = encrypt_key(enc_key, mac_key, pt)
        print(f"Test {i} (iv|ciphertext|tag hex): {to_hex(ct)}")

if __name__ == "__main__":
    main()