
import os
import secrets
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac

MAGIC = b"ENC1"
VERSION = 1
SALT_LENGTH = 16
IV_LENGTH = 12
TAG_LENGTH = 16
ITERATIONS = 210000


def encrypt_data(plaintext: str, passphrase: str) -> bytes:
    """Encrypt sensitive data using AES-256-GCM."""
    if not plaintext:
        raise ValueError("Plaintext cannot be empty")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    
    salt = secrets.token_bytes(SALT_LENGTH)
    iv = secrets.token_bytes(IV_LENGTH)
    
    key = _derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext_bytes, None)
    
    result = MAGIC + VERSION.to_bytes(4, 'big') + salt + iv + ciphertext_with_tag
    
    return result


def decrypt_data(encrypted_data: bytes, passphrase: str) -> str:
    """Decrypt sensitive data encrypted with AES-256-GCM."""
    if not encrypted_data:
        raise ValueError("Encrypted data cannot be empty")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    
    min_length = len(MAGIC) + 4 + SALT_LENGTH + IV_LENGTH + TAG_LENGTH
    if len(encrypted_data) < min_length:
        raise ValueError("Invalid encrypted data: too short")
    
    offset = 0
    magic = encrypted_data[offset:offset + len(MAGIC)]
    offset += len(MAGIC)
    
    if magic != MAGIC:
        raise ValueError("Invalid file format: magic mismatch")
    
    version = int.from_bytes(encrypted_data[offset:offset + 4], 'big')
    offset += 4
    
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")
    
    salt = encrypted_data[offset:offset + SALT_LENGTH]
    offset += SALT_LENGTH
    
    iv = encrypted_data[offset:offset + IV_LENGTH]
    offset += IV_LENGTH
    
    ciphertext_with_tag = encrypted_data[offset:]
    
    key = _derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
    except Exception:
        raise ValueError("Decryption failed: invalid passphrase or corrupted data")
    
    return plaintext.decode('utf-8')


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive encryption key from passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode('utf-8'))


def store_encrypted_data(filepath: str, data: str, passphrase: str) -> None:
    """Store encrypted sensitive data to file."""
    if not filepath:
        raise ValueError("Filepath cannot be empty")
    
    file_path = Path(filepath).resolve()
    parent = file_path.parent
    
    if not parent.exists():
        raise ValueError(f"Parent directory does not exist: {parent}")
    
    encrypted = encrypt_data(data, passphrase)
    
    temp_fd, temp_path = None, None
    try:
        import tempfile
        temp_fd = tempfile.NamedTemporaryFile(mode='wb', dir=parent, delete=False)
        temp_path = Path(temp_fd.name)
        temp_fd.write(encrypted)
        temp_fd.flush()
        os.fsync(temp_fd.fileno())
        temp_fd.close()
        
        try:
            os.chmod(temp_path, 0o600)
        except (OSError, AttributeError):
            pass
        
        temp_path.replace(file_path)
        
    except Exception as e:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass
        raise e


def retrieve_encrypted_data(filepath: str, passphrase: str) -> str:
    """Retrieve and decrypt sensitive data from file."""
    if not filepath:
        raise ValueError("Filepath cannot be empty")
    
    file_path = Path(filepath).resolve()
    
    if not file_path.exists():
        raise FileNotFoundError(f"File does not exist: {filepath}")
    
    if not file_path.is_file():
        raise ValueError(f"Path is not a regular file: {filepath}")
    
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    
    return decrypt_data(encrypted, passphrase)


def constant_time_equals(a: str, b: str) -> bool:
    """Constant time string comparison."""
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


def main() -> None:
    """Run test cases."""
    try:
        # Test Case 1: Basic encryption and decryption
        print("Test Case 1: Basic encryption/decryption")
        credit_card = "4532-1234-5678-9010"
        pass1 = "SecurePassphrase123!"
        encrypted1 = encrypt_data(credit_card, pass1)
        decrypted1 = decrypt_data(encrypted1, pass1)
        print(f"Success: {constant_time_equals(credit_card, decrypted1)}")
        
        # Test Case 2: Personal information
        print("\\nTest Case 2: Personal information")
        personal_info = "SSN:123-45-6789|Name:John Doe"
        pass2 = "AnotherSecurePass456$"
        encrypted2 = encrypt_data(personal_info, pass2)
        decrypted2 = decrypt_data(encrypted2, pass2)
        print(f"Success: {constant_time_equals(personal_info, decrypted2)}")
        
        # Test Case 3: File storage and retrieval
        print("\\nTest Case 3: File storage/retrieval")
        test_file = "test_sensitive_data.enc"
        test_data = "Account:9876543210|PIN:5432"
        pass3 = "FileTestPass789&"
        store_encrypted_data(test_file, test_data, pass3)
        retrieved = retrieve_encrypted_data(test_file, pass3)
        print(f"Success: {constant_time_equals(test_data, retrieved)}")
        Path(test_file).unlink(missing_ok=True)
        
        # Test Case 4: Wrong passphrase handling
        print("\\nTest Case 4: Wrong passphrase")
        data4 = "Sensitive:Data123"
        correct_pass = "CorrectPassword!"
        wrong_pass = "WrongPassword!"
        encrypted4 = encrypt_data(data4, correct_pass)
        try:
            decrypt_data(encrypted4, wrong_pass)
            print("Failed: Should have thrown exception")
        except ValueError:
            print("Success: Correctly rejected wrong passphrase")
        
        # Test Case 5: Empty input validation
        print("\\nTest Case 5: Input validation")
        try:
            encrypt_data("", "pass")
            print("Failed: Should have rejected empty plaintext")
        except ValueError:
            print("Success: Correctly rejected empty plaintext")
            
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
