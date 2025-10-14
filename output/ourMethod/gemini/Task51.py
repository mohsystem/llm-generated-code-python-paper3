import base64
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Constants
SALT_LENGTH_BYTES = 16
IV_LENGTH_BYTES = 12
TAG_LENGTH_BYTES = 16  # 128 bits
KEY_LENGTH_BYTES = 32  # 256 bits
PBKDF2_ITERATIONS = 600000
MAGIC_BYTES = b"ENC1"
VERSION = b"\x01"

def encrypt(plaintext: str, password: str) -> str:
    """Encrypts a string using AES-256-GCM with a key derived from a password."""
    
    # 1. Generate Salt and IV
    salt = secrets.token_bytes(SALT_LENGTH_BYTES)
    iv = secrets.token_bytes(IV_LENGTH_BYTES)

    # 2. Derive Key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    key = kdf.derive(password.encode('utf-8'))

    # 3. Encrypt
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext_bytes, None)

    # 4. Assemble Output: [magic][version][salt][iv][ciphertext+tag]
    encrypted_data = MAGIC_BYTES + VERSION + salt + iv + ciphertext_with_tag
    
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt(base64_ciphertext: str, password: str) -> str:
    """Decrypts a string encrypted with the corresponding encrypt function."""
    try:
        decoded_data = base64.b64decode(base64_ciphertext)
    except (ValueError, TypeError):
        raise ValueError("Invalid Base64 string")

    # 1. Parse Input
    header_len = len(MAGIC_BYTES) + 1 + SALT_LENGTH_BYTES + IV_LENGTH_BYTES
    if len(decoded_data) < header_len + TAG_LENGTH_BYTES:
        raise ValueError("Ciphertext is too short to be valid.")

    magic = decoded_data[:len(MAGIC_BYTES)]
    if magic != MAGIC_BYTES:
        raise ValueError("Invalid file format: magic bytes mismatch.")

    version = decoded_data[len(MAGIC_BYTES):len(MAGIC_BYTES) + 1]
    if version != VERSION:
        raise ValueError("Unsupported version.")

    offset = len(MAGIC_BYTES) + 1
    salt = decoded_data[offset:offset + SALT_LENGTH_BYTES]
    offset += SALT_LENGTH_BYTES
    iv = decoded_data[offset:offset + IV_LENGTH_BYTES]
    offset += IV_LENGTH_BYTES
    ciphertext_with_tag = decoded_data[offset:]

    # 2. Derive Key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    key = kdf.derive(password.encode('utf-8'))
    
    # 3. Decrypt
    try:
        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        return decrypted_bytes.decode('utf-8')
    except InvalidTag:
        raise ValueError("Decryption failed: authentication tag mismatch.")

def main():
    """Main function with test cases."""
    # In a real app, use a secure way to get the password
    password = "a_very_strong_password_!@#$"
    test_cases = [
        "Hello, World!",
        "",
        "This is a longer test sentence to see how it performs with more data.",
        "12345!@#$%^&*()_+-=`~",
        "こんにちは世界" # Unicode test
    ]

    print("Running 5 test cases...")

    for i, original_plaintext in enumerate(test_cases):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Original:    {original_plaintext}")
        try:
            encrypted = encrypt(original_plaintext, password)
            print(f"Encrypted:   {encrypted[:60]}...")

            decrypted = decrypt(encrypted, password)
            print(f"Decrypted:   {decrypted}")

            if original_plaintext == decrypted:
                print("Status:      SUCCESS")
            else:
                print("Status:      FAILURE")
        except (ValueError, Exception) as e:
            print(f"An error occurred during test case {i + 1}: {e}")

if __name__ == "__main__":
    main()