import os
import base64
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Constants based on security recommendations
AES_KEY_SIZE_BYTES = 32  # 256-bit
GCM_IV_LENGTH_BYTES = 12
GCM_TAG_LENGTH_BYTES = 16
SALT_LENGTH_BYTES = 16
PBKDF2_ITERATIONS = 600000

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derives a 256-bit key from a passphrase and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    return key

def encrypt(plaintext: str, passphrase: str) -> bytes:
    """
    Encrypts plaintext using AES-256-GCM with a key derived from the passphrase.
    Returns a byte string in the format: [salt(16)][iv(12)][ciphertext+tag]
    """
    try:
        salt = secrets.token_bytes(SALT_LENGTH_BYTES)
        key = derive_key(passphrase, salt)
        
        iv = secrets.token_bytes(GCM_IV_LENGTH_BYTES)
        
        aesgcm = AESGCM(key)
        
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext_bytes, None)
        
        return salt + iv + ciphertext_with_tag
    except Exception as e:
        # In a real app, log securely. For this example, re-raise.
        raise RuntimeError("Encryption failed") from e


def decrypt(encrypted_data: bytes, passphrase: str) -> Optional[str]:
    """
    Decrypts data encrypted by the encrypt function.
    Returns the original plaintext string, or None if decryption fails.
    """
    try:
        # Validate length before unpacking
        if len(encrypted_data) < SALT_LENGTH_BYTES + GCM_IV_LENGTH_BYTES + GCM_TAG_LENGTH_BYTES:
            return None

        salt = encrypted_data[:SALT_LENGTH_BYTES]
        iv = encrypted_data[SALT_LENGTH_BYTES : SALT_LENGTH_BYTES + GCM_IV_LENGTH_BYTES]
        ciphertext_with_tag = encrypted_data[SALT_LENGTH_BYTES + GCM_IV_LENGTH_BYTES:]
        
        key = derive_key(passphrase, salt)
        
        aesgcm = AESGCM(key)
        
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        
        return decrypted_bytes.decode('utf-8')
    except (InvalidTag, ValueError, TypeError):
        # InvalidTag is the expected error for wrong key or tampered data.
        # Other errors could indicate malformed input.
        # Fail closed by returning None.
        return None

def main():
    """Main function with test cases."""
    print("--- Cryptographic Key Management Demo ---")

    passphrase = "a_very-s3cur3-p@ssphr@se!"
    test_cases = [
        "Hello, World!",
        "This is a secret message.",
        "Another test case with some special characters: !@#$%^&*()",
        "Short",
        ""  # Empty string
    ]

    for i, original_plaintext in enumerate(test_cases):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Original:  {original_plaintext}")

        encrypted_data = encrypt(original_plaintext, passphrase)
        print(f"Encrypted (Base64): {base64.b64encode(encrypted_data).decode('utf-8')}")

        decrypted_plaintext = decrypt(encrypted_data, passphrase)
        print(f"Decrypted: {decrypted_plaintext}")
        print(f"Result: {'SUCCESS' if original_plaintext == decrypted_plaintext else 'FAILURE'}")

    print("\n--- Failure Test Cases ---")
    original_text = "Test for failure cases."
    encrypted = encrypt(original_text, passphrase)

    # Test 1: Wrong Passphrase
    print("\n1. Decrypting with wrong passphrase...")
    decrypted_wrong_pass = decrypt(encrypted, "wrong-passphrase")
    print(f"Decrypted: {decrypted_wrong_pass}")
    print(f"Result: {'SUCCESS (Decryption failed as expected)' if decrypted_wrong_pass is None else 'FAILURE'}")

    # Test 2: Tampered Ciphertext
    print("\n2. Decrypting with tampered ciphertext...")
    tampered_list = list(encrypted)
    tampered_list[-1] ^= 0x01  # Flip a bit in the tag
    tampered_encrypted = bytes(tampered_list)
    decrypted_tampered = decrypt(tampered_encrypted, passphrase)
    print(f"Decrypted: {decrypted_tampered}")
    print(f"Result: {'SUCCESS (Decryption failed as expected)' if decrypted_tampered is None else 'FAILURE'}")

if __name__ == "__main__":
    main()