import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Constants
KEY_SIZE_BYTES = 32  # 256 bits
IV_SIZE_BYTES = 16   # 128 bits for AES

def encrypt(plain_text: str, key: bytes, iv: bytes) -> bytes:
    """
    Creates a Cipher using AES in CBC mode and encrypts the given plaintext.

    Args:
        plain_text: The plaintext string to encrypt.
        key: The 32-byte (256-bit) key for encryption.
        iv: The 16-byte (128-bit) Initialization Vector.

    Returns:
        A byte string containing the encrypted ciphertext.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {KEY_SIZE_BYTES} bytes long.")
    if len(iv) != IV_SIZE_BYTES:
        raise ValueError(f"IV must be {IV_SIZE_BYTES} bytes long.")

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Add PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode('utf-8')) + padder.finalize()
    
    # Encrypt the padded data
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    
    return cipher_text

def main():
    """Main function with test cases."""
    # Generate a single, reusable key for the test cases
    key = os.urandom(KEY_SIZE_BYTES)
    print(f"Generated AES Key: {key.hex()}")
    print("----------------------------------------")

    test_cases = [
        "This is a secret message.",
        "The quick brown fox jumps over the lazy dog.",
        "AES encryption is secure!",
        "1234567890",
        "Another test case with some special characters !@#$%^&*()"
    ]

    for i, plain_text in enumerate(test_cases):
        print(f"Test Case {i + 1}")
        print(f"Plaintext: {plain_text}")

        # Generate a new, random IV for each encryption
        iv = os.urandom(IV_SIZE_BYTES)
        print(f"IV: {iv.hex()}")

        # Encrypt the data
        cipher_text = encrypt(plain_text, key, iv)
        
        # Prepend IV to ciphertext and encode in Base64
        encrypted_data = iv + cipher_text
        encoded_result = base64.b64encode(encrypted_data).decode('utf-8')

        print(f"Encrypted (Base64): {encoded_result}")
        print("----------------------------------------")


if __name__ == "__main__":
    main()