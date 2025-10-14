import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt(plain_text: str, key: bytes, iv: bytes) -> bytes:
    """
    Encrypts a plaintext string using AES/CBC/PKCS7Padding.
    
    Args:
        plain_text: The string to encrypt.
        key: The 16, 24, or 32-byte secret key.
        iv: The 16-byte initialization vector.

    Returns:
        The encrypted data as bytes.
    """
    if len(key) not in [16, 24, 32] or len(iv) != 16:
        raise ValueError("Invalid key or IV length.")

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    # PKCS7 padding is compatible with PKCS5 and is the standard for modern crypto libraries
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    # Plain text must be encoded to bytes before padding and encryption
    padded_data = padder.update(plain_text.encode('utf-8')) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def main():
    """Main function with test cases."""
    # Use a 128-bit key and IV (16 bytes).
    key = b'0123456789abcdef'
    iv = b'fedcba9876543210'

    test_cases = [
        "This is a test.",
        "Short",
        "This is a slightly longer plaintext message.",
        "Encrypt this key!",
        "AES CBC Mode Test"
    ]
    
    print("AES/CBC/PKCS7Padding Encryption Test Cases:")
    print(f"Key: {key.decode('utf-8')}")
    print(f"IV: {iv.decode('utf-8')}")
    print("----------------------------------------------")

    for i, plain_text in enumerate(test_cases):
        try:
            encrypted_bytes = encrypt(plain_text, key, iv)
            encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
            print(f"Test Case {i + 1}:")
            print(f"  Plaintext:  {plain_text}")
            print(f"  Encrypted (Base64): {encrypted_base64}")
            print()
        except Exception as e:
            print(f"An error occurred during encryption for test case {i + 1}: {e}")

if __name__ == "__main__":
    main()