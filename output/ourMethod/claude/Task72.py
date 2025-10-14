
import secrets
import struct
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
    if not passphrase or not salt or len(salt) != SALT_LENGTH:
        raise ValueError("Invalid passphrase or salt")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    return kdf.derive(passphrase.encode('utf-8'))


def encrypt_data(plaintext: str, passphrase: str) -> bytes:
    if plaintext is None or passphrase is None or not passphrase:
        raise ValueError("Invalid input parameters")
    
    salt = secrets.token_bytes(SALT_LENGTH)
    iv = secrets.token_bytes(IV_LENGTH)
    
    key = derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)
    
    result = MAGIC + struct.pack('B', VERSION) + salt + iv + ciphertext
    return result


def decrypt_data(encrypted_data: bytes, passphrase: str) -> str:
    if encrypted_data is None or passphrase is None or not passphrase:
        raise ValueError("Invalid input parameters")
    
    if len(encrypted_data) < len(MAGIC) + 1 + SALT_LENGTH + IV_LENGTH + TAG_LENGTH:
        raise ValueError("Invalid encrypted data length")
    
    offset = 0
    magic = encrypted_data[offset:offset + len(MAGIC)]
    offset += len(MAGIC)
    
    if magic != MAGIC:
        raise ValueError("Invalid file format")
    
    version = encrypted_data[offset]
    offset += 1
    
    if version != VERSION:
        raise ValueError("Unsupported version")
    
    salt = encrypted_data[offset:offset + SALT_LENGTH]
    offset += SALT_LENGTH
    
    iv = encrypted_data[offset:offset + IV_LENGTH]
    offset += IV_LENGTH
    
    ciphertext = encrypted_data[offset:]
    
    key = derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext, None)
    
    return plaintext_bytes.decode('utf-8')


def main():
    passphrase = "SecurePassphrase123!"
    
    test_cases = [
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
        "1234567890",
        "Special chars: !@#$%^&*()_+-=[]{}|;:',.<>?/`~",
        ""
    ]
    
    for i, test_data in enumerate(test_cases, 1):
        try:
            encrypted = encrypt_data(test_data, passphrase)
            decrypted = decrypt_data(encrypted, passphrase)
            result = "PASS" if test_data == decrypted else "FAIL"
            print(f"Test {i}: {result}")
        except Exception as e:
            print(f"Test {i}: FAIL - {str(e)}")


if __name__ == "__main__":
    main()
