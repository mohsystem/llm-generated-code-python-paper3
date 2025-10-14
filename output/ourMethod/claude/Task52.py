
import secrets
import os
from pathlib import Path
from typing import Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

MAGIC = b"ENC1"
VERSION = 1
SALT_LENGTH = 16
IV_LENGTH = 12
TAG_LENGTH = 16
PBKDF2_ITERATIONS = 210000
KEY_LENGTH = 32


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode('utf-8'))


def encrypt_file(input_path: str, passphrase: str, base_dir: str) -> bytes:
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    
    base = Path(base_dir).resolve()
    input_file = Path(input_path).resolve()
    
    if not input_file.is_relative_to(base):
        raise ValueError("Path outside base directory")
    
    if not input_file.is_file():
        raise ValueError("Input must be a regular file")
    
    if input_file.is_symlink():
        raise ValueError("Symlinks not allowed")
    
    plaintext = input_file.read_bytes()
    
    salt = secrets.token_bytes(SALT_LENGTH)
    iv = secrets.token_bytes(IV_LENGTH)
    
    key = derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
    
    encrypted_data = MAGIC + bytes([VERSION]) + salt + iv + ciphertext_with_tag
    
    return encrypted_data


def decrypt_file(encrypted_data: bytes, passphrase: str) -> bytes:
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    
    min_length = len(MAGIC) + 1 + SALT_LENGTH + IV_LENGTH + TAG_LENGTH
    if not encrypted_data or len(encrypted_data) < min_length:
        raise ValueError("Invalid encrypted data")
    
    offset = 0
    
    magic = encrypted_data[offset:offset + len(MAGIC)]
    offset += len(MAGIC)
    
    if not secrets.compare_digest(magic, MAGIC):
        raise ValueError("Invalid file format")
    
    version = encrypted_data[offset]
    offset += 1
    
    if version != VERSION:
        raise ValueError("Unsupported version")
    
    salt = encrypted_data[offset:offset + SALT_LENGTH]
    offset += SALT_LENGTH
    
    iv = encrypted_data[offset:offset + IV_LENGTH]
    offset += IV_LENGTH
    
    ciphertext_with_tag = encrypted_data[offset:]
    
    key = derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        return plaintext
    except InvalidTag:
        raise ValueError("Authentication failed: data may be corrupted or tampered")


def main():
    import tempfile
    import shutil
    
    temp_dir = tempfile.mkdtemp(prefix="test_encrypt_")
    
    try:
        print("Test 1: Basic encryption and decryption")
        test_file1 = Path(temp_dir) / "test1.txt"
        test_file1.write_text("Hello World", encoding='utf-8')
        encrypted1 = encrypt_file(str(test_file1), "password123", temp_dir)
        decrypted1 = decrypt_file(encrypted1, "password123")
        print(f"Result: {decrypted1.decode('utf-8')}")
        
        print("\\nTest 2: Different content")
        test_file2 = Path(temp_dir) / "test2.txt"
        test_file2.write_text("Secret Message 42", encoding='utf-8')
        encrypted2 = encrypt_file(str(test_file2), "strongpass", temp_dir)
        decrypted2 = decrypt_file(encrypted2, "strongpass")
        print(f"Result: {decrypted2.decode('utf-8')}")
        
        print("\\nTest 3: Wrong password")
        try:
            decrypt_file(encrypted1, "wrongpassword")
            print("ERROR: Should have failed")
        except ValueError as e:
            print(f"Correctly rejected: {e}")
        
        print("\\nTest 4: Path traversal prevention")
        try:
            encrypt_file("../outside.txt", "pass", temp_dir)
            print("ERROR: Should have rejected path")
        except Exception as e:
            print(f"Correctly rejected: {e}")
        
        print("\\nTest 5: Large content")
        test_file5 = Path(temp_dir) / "test5.txt"
        test_file5.write_bytes(b'A' * 10000)
        encrypted5 = encrypt_file(str(test_file5), "largepass", temp_dir)
        decrypted5 = decrypt_file(encrypted5, "largepass")
        print(f"Result: {len(decrypted5)} bytes decrypted")
        
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()
