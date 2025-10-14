# To run this code, you need to install the 'cryptography' library:
# pip install cryptography

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants
AES_KEY_SIZE = 32  # 32 bytes = 256 bits
IV_LENGTH_BYTE = 12 # 12 bytes = 96 bits is recommended for GCM

def encrypt(message: str, key: bytes) -> str:
    """
    Encrypts a message using AES-GCM algorithm.
    The IV (nonce) is prepended to the ciphertext.
    
    :param message: The plaintext message to encrypt.
    :param key: The 32-byte secret key for encryption.
    :return: A Base64 encoded string containing the IV and ciphertext with auth tag.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Invalid key size. Key must be {AES_KEY_SIZE} bytes.")

    # 1. Create a cipher for encryption
    aesgcm = AESGCM(key)
    
    # 2. Generate a secure random Initialization Vector (IV), also called a nonce
    iv = os.urandom(IV_LENGTH_BYTE)
    
    # 3. Encrypt the message
    message_bytes = message.encode('utf-8')
    cipher_text = aesgcm.encrypt(iv, message_bytes, None) # The result includes the authentication tag
    
    # 4. Concatenate IV and ciphertext and encode to Base64
    encrypted_message = base64.b64encode(iv + cipher_text).decode('utf-8')
    
    return encrypted_message

def main():
    """
    Main function to run test cases.
    """
    try:
        # Generate a new AES secret key
        # In a real application, this key would be securely stored and retrieved.
        secret_key = os.urandom(AES_KEY_SIZE)

        print(f"Generated AES-256 Key (Base64): {base64.b64encode(secret_key).decode('utf-8')}")
        print("--- Running 5 Test Cases ---")

        test_messages = [
            "This is the first secret message.",
            "Security is important for all applications.",
            "AES-GCM provides authenticated encryption.",
            "1234567890!@#$%^&*()_+",
            "A much longer message to test the encryption process to ensure it works correctly with varying lengths of input data. The quick brown fox jumps over the lazy dog."
        ]

        for i, message in enumerate(test_messages):
            print(f"\n--- Test Case {i + 1} ---")
            print(f"Original Message: {message}")
            encrypted_message = encrypt(message, secret_key)
            print(f"Encrypted (Base64): {encrypted_message}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()