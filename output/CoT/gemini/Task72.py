from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# IMPORTANT: Using a static, predictable IV is a major security vulnerability
# in modes like CBC. The IV should be random and unique for each encryption
# operation with the same key. This code is for demonstration purposes only,
# following the prompt's specific requirements.
STATIC_IV = b'1234567890123456'

def encrypt(plain_text: str, key: bytes) -> bytes:
    """
    Encrypts data using AES in CBC mode with a static IV.
    
    Args:
        plain_text: The string to encrypt.
        key: The secret key for encryption (must be 16, 24, or 32 bytes).
        
    Returns:
        The encrypted data as bytes, or None on failure.
    """
    try:
        # Pad the input data to match the block size required by the cipher.
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode('utf-8')) + padder.finalize()
        
        # Initialize a cipher using AES in CBC mode with the static IV.
        cipher = Cipher(algorithms.AES(key), modes.CBC(STATIC_IV), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the padded data.
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return None

def main():
    # IMPORTANT: Hardcoding keys is a security risk. In a real application,
    # use a secure key management system.
    # AES key must be 16, 24, or 32 bytes long.
    key = b'thisisakeyjklmno' # 16 bytes for AES-128

    test_cases = [
        "This is test case 1.",
        "Another test case with different data.",
        "Short",
        "A much longer string to test padding and multiple blocks of encryption.",
        "Test case 5 is the final one!"
    ]
    
    print("Encrypting using AES/CBC with a STATIC IV (INSECURE PRACTICE)")
    print("==========================================================")
    
    for i, plain_text in enumerate(test_cases, 1):
        encrypted_bytes = encrypt(plain_text, key)
        
        if encrypted_bytes:
            encrypted_hex = encrypted_bytes.hex()
            print(f"Test Case {i}:")
            print(f"  Plaintext:  {plain_text}")
            print(f"  Encrypted (Hex): {encrypted_hex}\n")

if __name__ == "__main__":
    main()