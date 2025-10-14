
import secrets
import base64
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


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from passphrase using PBKDF2-HMAC-SHA256."""
    if not passphrase or not isinstance(passphrase, str):
        raise ValueError("Passphrase must be a non-empty string")
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"Salt must be {SALT_LENGTH} bytes")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    return kdf.derive(passphrase.encode('utf-8'))


def encrypt(plaintext: str, passphrase: str) -> str:
    """Encrypt plaintext using AES-256-GCM with passphrase-derived key."""
    if not plaintext or not isinstance(plaintext, str):
        raise ValueError("Plaintext must be a non-empty string")
    if not passphrase or not isinstance(passphrase, str):
        raise ValueError("Passphrase must be a non-empty string")
    if len(plaintext) > 1048576:
        raise ValueError("Plaintext too long")
    
    salt = secrets.token_bytes(SALT_LENGTH)
    iv = secrets.token_bytes(IV_LENGTH)
    
    key = derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext_bytes, None)
    
    encrypted_data = MAGIC + bytes([VERSION]) + salt + iv + ciphertext_and_tag
    
    return base64.b64encode(encrypted_data).decode('ascii')


def decrypt(encrypted_data: str, passphrase: str) -> str:
    """Decrypt AES-256-GCM encrypted data with passphrase."""
    if not encrypted_data or not isinstance(encrypted_data, str):
        raise ValueError("Encrypted data must be a non-empty string")
    if not passphrase or not isinstance(passphrase, str):
        raise ValueError("Passphrase must be a non-empty string")
    
    try:
        data = base64.b64decode(encrypted_data)
    except Exception:
        raise ValueError("Invalid base64 encoding")
    
    min_length = len(MAGIC) + 1 + SALT_LENGTH + IV_LENGTH + TAG_LENGTH
    if len(data) < min_length:
        raise ValueError("Invalid encrypted data format")
    
    offset = 0
    magic = data[offset:offset + len(MAGIC)]
    offset += len(MAGIC)
    
    if magic != MAGIC:
        raise ValueError("Invalid magic bytes")
    
    version = data[offset]
    offset += 1
    
    if version != VERSION:
        raise ValueError("Unsupported version")
    
    salt = data[offset:offset + SALT_LENGTH]
    offset += SALT_LENGTH
    
    iv = data[offset:offset + IV_LENGTH]
    offset += IV_LENGTH
    
    ciphertext_and_tag = data[offset:]
    
    key = derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(iv, ciphertext_and_tag, None)
    except Exception:
        raise ValueError("Decryption failed: invalid tag or corrupted data")
    
    return plaintext_bytes.decode('utf-8')


def main():
    passphrase = "SecurePassphrase123!"
    
    test1 = "Hello, World!"
    encrypted1 = encrypt(test1, passphrase)
    decrypted1 = decrypt(encrypted1, passphrase)
    print(f"Test 1: {'PASS' if test1 == decrypted1 else 'FAIL'}")
    
    test2 = "Sensitive data 2024"
    encrypted2 = encrypt(test2, passphrase)
    decrypted2 = decrypt(encrypted2, passphrase)
    print(f"Test 2: {'PASS' if test2 == decrypted2 else 'FAIL'}")
    
    test3 = "Special chars: !@#$%^&*()"
    encrypted3 = encrypt(test3, passphrase)
    decrypted3 = decrypt(encrypted3, passphrase)
    print(f"Test 3: {'PASS' if test3 == decrypted3 else 'FAIL'}")
    
    test4 = "Unicode: 你好世界 🌍"
    encrypted4 = encrypt(test4, passphrase)
    decrypted4 = decrypt(encrypted4, passphrase)
    print(f"Test 4: {'PASS' if test4 == decrypted4 else 'FAIL'}")
    
    test5 = "Multiple lines\\nof text\\nfor testing"
    encrypted5 = encrypt(test5, passphrase)
    decrypted5 = decrypt(encrypted5, passphrase)
    print(f"Test 5: {'PASS' if test5 == decrypted5 else 'FAIL'}")


if __name__ == "__main__":
    main()
