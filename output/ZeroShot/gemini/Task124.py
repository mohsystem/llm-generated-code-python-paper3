import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# DISCLAIMER: This is a demonstration of cryptographic concepts.
# It is NOT a secure system for storing sensitive data in a production environment.
# Real-world security requires a much more comprehensive approach, including secure
# key management, which is not possible in this single-file example.

# --- Constants ---
# Using AES-GCM, which provides both confidentiality and authenticity.
AES_KEY_SIZE = 32  # 256-bit key
GCM_IV_LENGTH = 12  # 96 bits is recommended for GCM
GCM_TAG_LENGTH = 16 # 128-bit authentication tag
SALT_LENGTH = 16
PBKDF2_ITERATIONS = 600000  # Recommended by NIST

def encrypt(plain_text: str, password: str) -> str:
    """
    Encrypts a piece of data using a password.
    :param plain_text: The data to encrypt (string).
    :param password: The password to derive the encryption key from.
    :return: A string containing the encrypted data, formatted for storage.
    """
    if not isinstance(plain_text, str) or not isinstance(password, str):
        raise TypeError("Plain text and password must be strings.")

    # 1. Generate a random salt
    salt = os.urandom(SALT_LENGTH)

    # 2. Derive a key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    # 3. Encrypt using AES-GCM
    aesgcm = AESGCM(key)
    iv = os.urandom(GCM_IV_LENGTH)  # GCM calls it a "nonce"
    
    plain_text_bytes = plain_text.encode('utf-8')
    cipher_text = aesgcm.encrypt(iv, plain_text_bytes, None) # No additional authenticated data

    # 4. Combine salt, IV (nonce), and ciphertext for storage
    # Using Base64 encoding for each part makes it easy to parse
    b64_salt = base64.b64encode(salt).decode('utf-8')
    b64_iv = base64.b64encode(iv).decode('utf-8')
    b64_cipher_text = base64.b64encode(cipher_text).decode('utf-8')

    return f"{b64_salt}:{b64_iv}:{b64_cipher_text}"

def decrypt(encrypted_data: str, password: str) -> str:
    """
    Decrypts a piece of data using a password.
    :param encrypted_data: The encrypted data string from the encrypt function.
    :param password: The password used for the original encryption.
    :return: The original plaintext data.
    """
    if not isinstance(encrypted_data, str) or not isinstance(password, str):
        raise TypeError("Encrypted data and password must be strings.")
        
    try:
        # 1. Decode and split the components
        b64_salt, b64_iv, b64_cipher_text = encrypted_data.split(':')
        salt = base64.b64decode(b64_salt)
        iv = base64.b64decode(b64_iv)
        cipher_text = base64.b64decode(b64_cipher_text)
    except (ValueError, TypeError) as e:
        raise ValueError("Invalid encrypted data format") from e

    # 2. Re-derive the key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    # 3. Decrypt the data
    aesgcm = AESGCM(key)
    try:
        decrypted_bytes = aesgcm.decrypt(iv, cipher_text, None)
        return decrypted_bytes.decode('utf-8')
    except InvalidTag as e:
        # This is critical! It means the password was wrong or the data was tampered with.
        raise ValueError("Decryption failed: Invalid password or corrupted data") from e


def main():
    """Main function with test cases."""
    print("Running Python Tests...")
    password = "a-very-strong-password-!@#$"

    test_data = [
        "1234-5678-9012-3456",  # Test Case 1: Credit Card
        "{\"name\":\"John Doe\", \"ssn\":\"000-00-0000\"}",  # Test Case 2: JSON data
        "My secret diary entry.",  # Test Case 3: Simple text
        "",  # Test Case 4: Empty string
        "Data with special characters: <>?`|~"  # Test Case 5: Special characters
    ]

    for i, original_data in enumerate(test_data):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Original:    {original_data}")
        try:
            # Encryption
            encrypted = encrypt(original_data, password)
            print(f"Encrypted:   {encrypted}")

            # Decryption (Correct Password)
            decrypted = decrypt(encrypted, password)
            print(f"Decrypted:   {decrypted}")

            # Verification
            if original_data != decrypted:
                print("FAILURE: Decrypted data does not match original data.")
            else:
                print("SUCCESS: Data integrity verified.")
            
            # Decryption (Incorrect Password)
            print("Testing with incorrect password...")
            try:
                decrypt(encrypted, "wrong-password")
                print("FAILURE: Decryption with wrong password should have failed but didn't.")
            except ValueError as e:
                print(f"SUCCESS: Decryption failed as expected with wrong password. ({e})")
        except Exception as e:
            print(f"An error occurred during test case {i + 1}: {e}")

if __name__ == "__main__":
    main()