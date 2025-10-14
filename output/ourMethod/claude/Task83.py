
import os
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"ENC1"
VERSION = 1
SALT_LENGTH = 16
IV_LENGTH = 12
TAG_LENGTH = 16
ITERATIONS = 210000


def encrypt_data(passphrase: str, data_to_encrypt: bytes) -> bytes:
    """Encrypts data using AES-GCM with PBKDF2 key derivation."""
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    if not data_to_encrypt:
        raise ValueError("Data to encrypt cannot be empty")
    
    salt = secrets.token_bytes(SALT_LENGTH)
    iv = secrets.token_bytes(IV_LENGTH)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, data_to_encrypt, None)
    
    result = MAGIC + bytes([VERSION]) + salt + iv + ciphertext_with_tag
    
    return result


def decrypt_data(passphrase: str, encrypted_data: bytes) -> bytes:
    """Decrypts data encrypted with encrypt_data."""
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    
    min_length = len(MAGIC) + 1 + SALT_LENGTH + IV_LENGTH + TAG_LENGTH
    if not encrypted_data or len(encrypted_data) < min_length:
        raise ValueError("Invalid encrypted data")
    
    offset = 0
    magic = encrypted_data[offset:offset + len(MAGIC)]
    offset += len(MAGIC)
    
    if magic != MAGIC:
        raise ValueError("Invalid magic header")
    
    version = encrypted_data[offset]
    offset += 1
    
    if version != VERSION:
        raise ValueError("Unsupported version")
    
    salt = encrypted_data[offset:offset + SALT_LENGTH]
    offset += SALT_LENGTH
    
    iv = encrypted_data[offset:offset + IV_LENGTH]
    offset += IV_LENGTH
    
    ciphertext_with_tag = encrypted_data[offset:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
    
    return plaintext


def main():
    print("Test Case 1: Basic encryption/decryption")
    passphrase1 = "strongPassphrase123!"
    data1 = b"Hello, World!"
    encrypted1 = encrypt_data(passphrase1, data1)
    decrypted1 = decrypt_data(passphrase1, encrypted1)
    print(f"Original: {data1.decode('utf-8')}")
    print(f"Decrypted: {decrypted1.decode('utf-8')}")
    print(f"Match: {data1 == decrypted1}")
    print()
    
    print("Test Case 2: Encrypt sensitive key data")
    passphrase2 = "mySecureKey2023$"
    key_data = b"API_KEY_12345_SECRET"
    encrypted2 = encrypt_data(passphrase2, key_data)
    decrypted2 = decrypt_data(passphrase2, encrypted2)
    print(f"Key Match: {key_data == decrypted2}")
    print()
    
    print("Test Case 3: Different passphrase fails")
    passphrase3a = "correctPassword"
    passphrase3b = "wrongPassword"
    data3 = b"Secret Message"
    encrypted3 = encrypt_data(passphrase3a, data3)
    try:
        decrypt_data(passphrase3b, encrypted3)
        print("ERROR: Should have failed with wrong passphrase")
    except Exception as e:
        print("Correctly rejected wrong passphrase")
    print()
    
    print("Test Case 4: Encrypt binary data")
    passphrase4 = "binaryDataKey!@#"
    binary_data = bytes([0x00, 0x01, 0x02, 0xFF, 0xFE])
    encrypted4 = encrypt_data(passphrase4, binary_data)
    decrypted4 = decrypt_data(passphrase4, encrypted4)
    print(f"Binary Match: {binary_data == decrypted4}")
    print()
    
    print("Test Case 5: Invalid input handling")
    try:
        encrypt_data("", data1)
        print("ERROR: Should have rejected empty passphrase")
    except ValueError:
        print("Correctly rejected empty passphrase")
    try:
        encrypt_data(passphrase1, b"")
        print("ERROR: Should have rejected empty data")
    except ValueError:
        print("Correctly rejected empty data")


if __name__ == "__main__":
    main()
