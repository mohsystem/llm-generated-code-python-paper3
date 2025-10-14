import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# AES-256-GCM is a secure, authenticated encryption mode.
IV_LENGTH = 12  # GCM standard IV size is 96 bits (12 bytes)
TAG_LENGTH = 16 # GCM standard tag size is 128 bits (16 bytes)

def encrypt(plain_text: str, key: bytes) -> str:
    """
    Encrypts a message using AES-256-GCM.
    
    Args:
        plain_text: The string message to encrypt.
        key: A 32-byte (256-bit) secret key.

    Returns:
        A base64 encoded string of the format [IV][Ciphertext][Tag].
    """
    if len(key) != 32:
        raise ValueError("Invalid key size. Key must be 32 bytes for AES-256.")

    # 1. Generate a random, non-repeating IV for each encryption
    iv = os.urandom(IV_LENGTH)

    # 2. Create an AES-GCM Cipher object
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # 3. Encrypt the plaintext. GCM mode will handle the authentication tag.
    cipher_text = encryptor.update(plain_text.encode('utf-8')) + encryptor.finalize()

    # Combine IV, ciphertext, and the authentication tag for transport
    encrypted_message = iv + cipher_text + encryptor.tag

    # Base64 encode the combined message for safe transport/storage
    return base64.b64encode(encrypted_message).decode('utf-8')


def main():
    """Main function with test cases."""
    # In a real application, this key should be managed securely and not hardcoded.
    key = os.urandom(32) # 256-bit key
    print(f"Using Secret Key (Base64): {base64.b64encode(key).decode('utf-8')}")
    print("---")

    test_cases = [
        "This is a secret message.",
        "Hello, World!",
        "Cryptography is fascinating.",
        "AES-GCM provides authenticated encryption.",
        "12345!@#$%^"
    ]

    for i, plain_text in enumerate(test_cases):
        try:
            print(f"Test Case {i + 1}")
            print(f"Original:  {plain_text}")
            encrypted_text = encrypt(plain_text, key)
            print(f"Encrypted: {encrypted_text}\n")
        except Exception as e:
            print(f"An error occurred: {e}\n")

if __name__ == "__main__":
    main()