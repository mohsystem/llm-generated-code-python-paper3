import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import base64
from typing import Optional

SALT_LENGTH_BYTES = 16
IV_LENGTH_BYTES = 12
KEY_LENGTH_BYTES = 32  # For AES-256
PBKDF2_ITERATIONS = 600000

def encrypt(plaintext: str, passphrase: str) -> bytes:
    """Encrypts plaintext using AES-256-GCM with a key derived from a passphrase."""
    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("Plaintext must be a non-empty string.")
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("Passphrase must be a non-empty string.")

    salt = os.urandom(SALT_LENGTH_BYTES)
    iv = os.urandom(IV_LENGTH_BYTES)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode('utf-8')
    
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext_bytes, None)
    
    # The format is salt + iv + ciphertext_and_tag
    return salt + iv + ciphertext_and_tag

def decrypt(ciphertext_blob: bytes, passphrase: str) -> Optional[str]:
    """Decrypts a ciphertext blob, returning the plaintext string or None on failure."""
    if not isinstance(ciphertext_blob, bytes) or not ciphertext_blob:
        return None
    if not isinstance(passphrase, str) or not passphrase:
        return None

    # AES-GCM tag is 16 bytes. Minimum length is salt + iv + tag.
    if len(ciphertext_blob) < SALT_LENGTH_BYTES + IV_LENGTH_BYTES + 16:
        return None
        
    try:
        salt = ciphertext_blob[:SALT_LENGTH_BYTES]
        iv = ciphertext_blob[SALT_LENGTH_BYTES:SALT_LENGTH_BYTES + IV_LENGTH_BYTES]
        ciphertext_and_tag = ciphertext_blob[SALT_LENGTH_BYTES + IV_LENGTH_BYTES:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH_BYTES,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode('utf-8'))
        
        aesgcm = AESGCM(key)
        
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext_and_tag, None)
        return decrypted_bytes.decode('utf-8')
    except (InvalidTag, ValueError, UnicodeDecodeError):
        # Failure can be due to wrong passphrase, corrupt data, or other issues.
        # Return None to prevent leaking information.
        return None

def main():
    """Main function with test cases."""
    test_passphrases = [
        "correct-horse-battery-staple",
        "Tr0ub4dor&3",
        "!@#$%^&*()_+",
        "a long passphrase with spaces and punctuation",
        "short"
    ]
    test_data = [
        "Credit Card: 1234-5678-9012-3456",
        "SSN: 000-00-0000",
        "{\"user\":\"admin\",\"password\":\"password123\"}",
        "This is a secret message.",
        "Another piece of sensitive info."
    ]

    for i in range(5):
        print(f"--- Test Case {i + 1} ---")
        original_data = test_data[i]
        passphrase = test_passphrases[i]
        print(f"Original: {original_data}")
        print(f"Passphrase: {passphrase}")

        # Encryption
        encrypted_data = encrypt(original_data, passphrase)
        print(f"Encrypted (Base64): {base64.b64encode(encrypted_data).decode('ascii')}")

        # Decryption (Success Case)
        decrypted_data = decrypt(encrypted_data, passphrase)
        print(f"Decrypted (Success): {decrypted_data}")
        if decrypted_data == original_data:
            print("SUCCESS: Decrypted data matches original.")
        else:
            print("FAILURE: Decrypted data does NOT match original.")

        # Decryption (Failure Case)
        failed_decryption = decrypt(encrypted_data, "wrong-password")
        if failed_decryption is None:
            print("SUCCESS: Decryption failed as expected with wrong passphrase.")
        else:
            print("FAILURE: Decryption succeeded with wrong passphrase.")
        print()

if __name__ == "__main__":
    main()