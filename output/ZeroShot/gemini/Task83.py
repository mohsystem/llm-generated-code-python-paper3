import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Constants for AES-256
KEY_SIZE_BYTES = 32  # 256 bits
IV_SIZE_BYTES = 16   # 128 bits for AES block size

def encrypt(plain_text: str, key: bytes) -> bytes:
    """
    Creates a Cipher using AES-256-CBC, encrypts the given plaintext,
    and returns the IV prepended to the ciphertext.

    :param plain_text: The string to encrypt.
    :param key: The 256-bit (32-byte) key for encryption.
    :return: A bytes object containing the IV followed by the ciphertext.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {KEY_SIZE_BYTES} bytes long.")

    # 1. Generate a cryptographically strong random IV
    iv = os.urandom(IV_SIZE_BYTES)
    
    # 2. Setup cipher and encryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    # 3. Apply PKCS7 padding to the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    plain_text_bytes = plain_text.encode('utf-8')
    padded_data = padder.update(plain_text_bytes) + padder.finalize()
    
    # 4. Encrypt the padded data
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    
    # 5. Prepend the IV to the ciphertext and return
    return iv + cipher_text

def main():
    """Main function with 5 test cases."""
    try:
        # Generate a secure AES key. In a real application, manage this key securely.
        secret_key = os.urandom(KEY_SIZE_BYTES)
        
        print(f"Using AES Key (Base64): {base64.b64encode(secret_key).decode('utf-8')}")
        print("--- Running 5 Test Cases ---")
        
        test_cases = [
            "This is the first test case.",
            "Encrypting another piece of data.",
            "AES in CBC mode is secure with a random IV.",
            "A short string.",
            "A much longer string to test padding and block chaining properly, ensuring everything works as expected for various lengths of input data."
        ]

        for i, plain_text in enumerate(test_cases):
            print(f"\n--- Test Case {i + 1} ---")
            print(f"Plaintext: {plain_text}")
            
            encrypted_data = encrypt(plain_text, secret_key)
            
            print(f"Encrypted (Base64): {base64.b64encode(encrypted_data).decode('utf-8')}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()