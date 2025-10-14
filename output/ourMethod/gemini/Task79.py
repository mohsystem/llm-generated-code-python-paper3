import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# --- Constants ---
SALT_SIZE = 16  # bytes
IV_SIZE = 12    # bytes
KEY_SIZE = 32   # bytes (256 bits)
TAG_SIZE = 16   # bytes (128 bits)
PBKDF2_ITERATIONS = 210000

def encrypt(plaintext: bytes, password: bytes) -> bytes:
    """
    Encrypts a plaintext message using a password.
    
    Args:
        plaintext: The message to encrypt, as bytes.
        password: The password to derive the key from, as bytes.
        
    Returns:
        A byte string containing salt || iv || ciphertext || tag.
    """
    try:
        # 1. Use a cryptographic backend
        backend = default_backend()

        # 2. Generate a cryptographically secure random salt and IV
        salt = secrets.token_bytes(SALT_SIZE)
        iv = secrets.token_bytes(IV_SIZE)

        # 3. Derive the encryption key from the password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=backend
        )
        key = kdf.derive(password)

        # 4. Create and use an AES-GCM cipher for encryption
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)

        # 5. Concatenate salt, IV, and the encrypted data (ciphertext + tag)
        return salt + iv + ciphertext_with_tag
    except Exception as e:
        # In a real application, use proper logging.
        print(f"An error occurred during encryption: {e}")
        return b''

def main():
    """Main function with test cases."""
    password = b"aVeryStrongPassword!123"
    
    test_cases = [
        b"Hello, World!",
        b"This is a secret message.",
        b"",  # Empty string
        b"Short",
        b"A much longer message to test the encryption process with more blocks of data to see how it handles it."
    ]

    for i, plaintext in enumerate(test_cases, 1):
        print(f"--- Test Case {i} ---")
        print(f"Plaintext: {plaintext.decode('utf-8')}")
        
        encrypted_data = encrypt(plaintext, password)
        
        if encrypted_data:
            print(f"Encrypted (Base64): {base64.b64encode(encrypted_data).decode('utf-8')}")
        else:
            print("Encryption failed.")
        print()

if __name__ == "__main__":
    main()