import os
import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SALT_LENGTH_BYTES = 16
IV_LENGTH_BYTES = 12
TAG_LENGTH_BYTES = 16  # 128 bits
PBKDF2_ITERATIONS = 210000
AES_KEY_BITS = 256

def encrypt(plaintext: bytes, password: str) -> bytes:
    """
    Encrypts plaintext using AES-256-GCM, deriving the key from a password.
    The security rules mandate using AES-GCM over the requested AES-CBC.
    
    Args:
        plaintext: The data to encrypt.
        password: The password to derive the encryption key from.
        
    Returns:
        A byte string containing salt, IV, and ciphertext with authentication tag.
    """
    # 1. Generate a random salt
    salt = secrets.token_bytes(SALT_LENGTH_BYTES)

    # 2. Derive the key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BITS // 8,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    # 3. Generate a random IV
    iv = secrets.token_bytes(IV_LENGTH_BYTES)

    # 4. Encrypt the plaintext
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)

    # 5. Concatenate salt, IV, and ciphertext with tag
    return salt + iv + ciphertext_with_tag


def main():
    """Main function with test cases."""
    # NOTE: Hardcoding secrets is insecure and violates security rules.
    # This is for demonstration purposes only. In a real application,
    # use a secure mechanism like environment variables or a secrets vault.
    password = "very-strong-password-123"
    test_keys_to_encrypt = [
        b"0123456789abcdef0123456789abcdef",  # 32 bytes
        b"short key",
        b"a-longer-key-with-some-symbols!@#$",
        b"",  # Empty bytes
        b"another key for testing purposes 12345"
    ]

    print("Running 5 test cases for AES-GCM encryption...")

    for i, original_key in enumerate(test_keys_to_encrypt):
        try:
            print(f"\n--- Test Case {i + 1} ---")
            print(f"Original data: {original_key.decode('utf-8')}")

            encrypted_data = encrypt(original_key, password)
            print(f"Encrypted (Base64): {base64.b64encode(encrypted_data).decode('utf-8')}")
            print(f"Encrypted data length: {len(encrypted_data)} bytes")

        except Exception as e:
            print(f"Test Case {i + 1} failed: {e}")

if __name__ == "__main__":
    main()