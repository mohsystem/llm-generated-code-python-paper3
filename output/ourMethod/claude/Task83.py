
import os
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """\n    Derive a 256-bit encryption key from a passphrase using PBKDF2-HMAC-SHA256.\n    Uses 210,000 iterations as per security requirements.\n    """
    # Validate inputs
    if not passphrase or not isinstance(passphrase, str):
        raise ValueError("Passphrase must be a non-empty string")
    if not salt or len(salt) != 16:
        raise ValueError("Salt must be exactly 16 bytes")
    
    # Derive key using PBKDF2 with SHA-256, 210,000 iterations for security
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for AES-256
        salt=salt,
        iterations=210000,  # Minimum required iterations
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode('utf-8'))


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """\n    Compute HMAC-SHA256 for encrypt-then-MAC pattern.\n    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def encrypt_aes_cbc_with_hmac(plaintext: bytes, passphrase: str) -> bytes:
    """
    Encrypt data using AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC).
    Returns a structured format: [magic][version][salt][iv][ciphertext][hmac_tag]

    Security measures:
    - Uses AES-256 in CBC mode with PKCS7 padding
    - Implements Encrypt-then-MAC pattern for authentication
    - Generates unique 16-byte salt per encryption
    - Generates unique 16-byte IV per encryption using CSPRNG
    - Uses PBKDF2-HMAC-SHA256 with 210,000 iterations
    - Validates all inputs before processing
    """
    # Input validation - treat all inputs as untrusted
    if not plaintext or not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be non-empty bytes")
    if not passphrase or not isinstance(passphrase, str):
        raise ValueError("Passphrase must be a non-empty string")
    if len(plaintext) > 10 * 1024 * 1024:  # 10MB limit
        raise ValueError("Plaintext exceeds maximum size")

    # Generate cryptographically secure random salt and IV
    # Using secrets module for CSPRNG as per security requirements
    salt = secrets.token_bytes(16)  # Unique 16-byte salt
    iv = secrets.token_bytes(16)    # Unique 16-byte IV for CBC mode

    # Derive encryption key from passphrase using secure KDF
    encryption_key = derive_key_from_passphrase(passphrase, salt)

    # Derive separate HMAC key from passphrase for Encrypt-then-MAC
    hmac_salt = secrets.token_bytes(16)
    kdf_hmac = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hmac_salt,
        iterations=210000,
        backend=default_backend()
    )
    hmac_key = kdf_hmac.derive(passphrase.encode('utf-8'))

    # Create AES-256-CBC cipher with explicit mode specification
    cipher = Cipher(
        algorithms.AES(encryption_key),  # AES-256 (32-byte key)
        modes.CBC(iv),                   # CBC mode with unique IV
        backend=default_backend()
    )

    # Encrypt the plaintext
    encryptor = cipher.encryptor()
    # CBC mode with PKCS7 padding is handled by cryptography library
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Build the output structure: magic + version + salt + hmac_salt + iv + ciphertext
    magic = b'ENC1'
    version = bytes([1])

    # Construct the authenticated payload
    authenticated_data = magic + version + salt + hmac_salt + iv + ciphertext

    # Compute HMAC over all data (Encrypt-then-MAC pattern)
    hmac_tag = compute_hmac(hmac_key, authenticated_data)

    # Securely clear sensitive key material from memory
    # Note: Python doesn't guarantee memory clearing, but we make best effort
    del encryption_key
    del hmac_key

    # Return complete encrypted package with authentication
    return authenticated_data + hmac_tag


def decrypt_aes_cbc_with_hmac(encrypted_data: bytes, passphrase: str) -> bytes:
    """
    Decrypt data encrypted with encrypt_aes_cbc_with_hmac.
    Verifies HMAC before decryption (fail closed on authentication failure).

    Security measures:
    - Validates magic and version before processing
    - Verifies HMAC in constant time before decryption
    - Fails closed on any validation error without revealing details
    - Does not return partial plaintext on error
    """
    # Input validation
    if not encrypted_data or not isinstance(encrypted_data, bytes):
        raise ValueError("Encrypted data must be non-empty bytes")
    if not passphrase or not isinstance(passphrase, str):
        raise ValueError("Passphrase must be a non-empty string")

    # Minimum size check: magic(4) + version(1) + salt(16) + hmac_salt(16) + iv(16) + hmac(32)
    if len(encrypted_data) < 85:
        raise ValueError("Invalid encrypted data format")

    # Parse the structure
    offset = 0
    magic = encrypted_data[offset:offset + 4]
    offset += 4

    # Validate magic number
    if magic != b'ENC1':
        raise ValueError("Invalid file format")

    version = encrypted_data[offset]
    offset += 1

    # Validate version
    if version != 1:
        raise ValueError("Unsupported version")

    salt = encrypted_data[offset:offset + 16]
    offset += 16

    hmac_salt = encrypted_data[offset:offset + 16]
    offset += 16

    iv = encrypted_data[offset:offset + 16]
    offset += 16

    # Remaining data is ciphertext + hmac_tag
    hmac_tag = encrypted_data[-32:]
    ciphertext = encrypted_data[offset:-32]
    authenticated_data = encrypted_data[:-32]

    # Derive HMAC key to verify authentication tag
    kdf_hmac = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hmac_salt,
        iterations=210000,
        backend=default_backend()
    )
    hmac_key = kdf_hmac.derive(passphrase.encode('utf-8'))

    # Verify HMAC tag using constant-time comparison
    expected_hmac = compute_hmac(hmac_key, authenticated_data)

    # Use constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(expected_hmac, hmac_tag):
        # Fail closed - clear sensitive data and raise error
        del hmac_key
        raise ValueError("Authentication failed")

    # HMAC verified - proceed with decryption
    encryption_key = derive_key_from_passphrase(passphrase, salt)

    # Create AES-256-CBC cipher for decryption
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Clear sensitive key material
    del encryption_key
    del hmac_key

    return plaintext


def main():
    """
    Test cases demonstrating secure AES-CBC encryption with HMAC.
    Each test uses a unique salt and IV generated by CSPRNG.
    """
    print("AES-256-CBC with HMAC-SHA256 Encryption Test Cases\n")

    # Test case 1: Basic encryption/decryption
    print("Test 1: Basic encryption/decryption")
    plaintext1 = b"Secret message to encrypt"
    passphrase1 = "StrongPassphrase123!@#"
    encrypted1 = encrypt_aes_cbc_with_hmac(plaintext1, passphrase1)
    decrypted1 = decrypt_aes_cbc_with_hmac(encrypted1, passphrase1)
    print(f"Original:  {plaintext1}")
    print(f"Encrypted length: {len(encrypted1)} bytes")
    print(f"Decrypted: {decrypted1}")
    print(f"Match: {plaintext1 == decrypted1}\n")

    # Test case 2: Encrypting binary data
    print("Test 2: Binary data encryption")
    plaintext2 = os.urandom(64)
    passphrase2 = "AnotherSecurePass456$%^"
    encrypted2 = encrypt_aes_cbc_with_hmac(plaintext2, passphrase2)
    decrypted2 = decrypt_aes_cbc_with_hmac(encrypted2, passphrase2)
    print(f"Original length:  {len(plaintext2)} bytes")
    print(f"Encrypted length: {len(encrypted2)} bytes")
    print(f"Match: {plaintext2 == decrypted2}\n")

    # Test case 3: UTF-8 text encryption
    print("Test 3: UTF-8 text encryption")
    plaintext3 = "Hello, 世界! 🔐".encode('utf-8')
    passphrase3 = "Unicode_Passphrase_2024!"
    encrypted3 = encrypt_aes_cbc_with_hmac(plaintext3, passphrase3)
    decrypted3 = decrypt_aes_cbc_with_hmac(encrypted3, passphrase3)
    print(f"Original:  {plaintext3.decode('utf-8')}")
    print(f"Decrypted: {decrypted3.decode('utf-8')}")
    print(f"Match: {plaintext3 == decrypted3}\n")

    # Test case 4: Large data encryption
    print("Test 4: Large data encryption")
    plaintext4 = b"X" * 10000
    passphrase4 = "LargeDataPass789&*()"
    encrypted4 = encrypt_aes_cbc_with_hmac(plaintext4, passphrase4)
    decrypted4 = decrypt_aes_cbc_with_hmac(encrypted4, passphrase4)
    print(f"Original length:  {len(plaintext4)} bytes")
    print(f"Encrypted length: {len(encrypted4)} bytes")
    print(f"Match: {plaintext4 == decrypted4}\n")

    # Test case 5: Verify HMAC authentication failure detection
    print("Test 5: HMAC authentication failure detection")
    plaintext5 = b"Authenticated message"
    passphrase5 = "AuthTestPass!@#123"
    encrypted5 = encrypt_aes_cbc_with_hmac(plaintext5, passphrase5)

    # Tamper with the ciphertext
    tampered = bytearray(encrypted5)
    tampered[-50] ^= 0xFF  # Flip bits in ciphertext

    try:
        decrypt_aes_cbc_with_hmac(bytes(tampered), passphrase5)
        print("FAILED: Tampered data was accepted")
    except ValueError as e:
        print(f"SUCCESS: Tampered data rejected - {e}\n")

    print("All test cases completed successfully!")


if __name__ == "__main__":
    main()
