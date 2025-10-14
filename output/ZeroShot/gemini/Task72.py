import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Static Initialization Vector (IV). For AES, this is 16 bytes.
# In a real-world application, IV should be random and unique for each encryption.
STATIC_IV = bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
])

def encrypt(key, plaintext):
    """
    Encrypts data using AES/CBC/PKCS7 with a static IV.

    Args:
        key (bytes): The encryption key (must be 16, 24, or 32 bytes).
        plaintext (str): The string data to encrypt.

    Returns:
        bytes: The encrypted data, or None on error.
    """
    if not isinstance(key, bytes) or len(key) not in [16, 24, 32]:
        print("Error: Invalid key size. Key must be 16, 24, or 32 bytes long.")
        return None
    if not isinstance(plaintext, str):
        print("Error: Plaintext must be a string.")
        return None

    try:
        # The backend for cryptographic operations
        backend = default_backend()
        
        # Initialize cipher with AES algorithm and CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(STATIC_IV), backend=backend)
        encryptor = cipher.encryptor()

        # Pad the plaintext to match the block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        plaintext_bytes = plaintext.encode('utf-8')
        padded_data = padder.update(plaintext_bytes) + padder.finalize()
        
        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return ciphertext
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return None

def main():
    """Main function with test cases."""
    # A 16-byte (128-bit) key for demonstration.
    # In a real application, use a secure key management system.
    key = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    ])

    test_cases = [
        "Hello, World!",
        "16-byte message!",  # Exactly one block
        "This is a longer test message for AES CBC encryption.",
        "",  # Empty string
        "123!@#$%^&*()"
    ]
    
    print("Python AES/CBC Encryption with Static IV")
    print("---------------------------------------")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case #{i}")
        print(f"Plaintext: {test_case}")
        encrypted_data = encrypt(key, test_case)
        if encrypted_data:
            print(f"Encrypted (Base64): {base64.b64encode(encrypted_data).decode('utf-8')}")
        else:
            print("Encryption failed.")
        print()

if __name__ == "__main__":
    main()