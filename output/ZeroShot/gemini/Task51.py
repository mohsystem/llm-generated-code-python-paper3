import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-GCM parameters
AES_KEY_SIZE = 32  # 256-bit key
GCM_IV_LENGTH = 12 # 96-bit nonce (IV)

def generate_key() -> bytes:
    """
    Generates a cryptographically secure key of AES_KEY_SIZE bytes.
    In a real application, you must manage keys securely (e.g., using a KMS or HSM).
    """
    return os.urandom(AES_KEY_SIZE)

def encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypts a plaintext string using AES-GCM.
    The output is a Base64 encoded string containing the nonce (IV), 
    followed by the ciphertext and auth tag.

    Args:
        plaintext: The string to encrypt.
        key: The 32-byte secret key for encryption.

    Returns:
        A Base64 encoded string representing the encrypted data (nonce + ciphertext).
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes.")
        
    # Generate a random, non-repeating nonce for each encryption
    nonce = os.urandom(GCM_IV_LENGTH)

    # Initialize AESGCM with the key
    aesgcm = AESGCM(key)
    
    plaintext_bytes = plaintext.encode('utf-8')
    
    # Encrypt the plaintext. The result includes the authentication tag.
    ciphertext_bytes = aesgcm.encrypt(nonce, plaintext_bytes, None)

    # Prepend the nonce to the ciphertext. This is a standard way to transport the nonce,
    # as it is not secret and is required for decryption.
    cipher_message = nonce + ciphertext_bytes
    
    # Return the result as a Base64 encoded string for safe transport
    return base64.b64encode(cipher_message).decode('utf-8')

def main():
    """Main function to run test cases."""
    try:
        # IMPORTANT: In a real-world application, the key must be securely
        # managed and not hardcoded or generated on the fly like this.
        # This is for demonstration purposes only.
        key = generate_key()
        
        test_cases = [
            "This is a secret message.",
            "1234567890",
            "!@#$%^&*()_+",
            "A very long message to test the encryption with a larger payload to see how it performs and handles bigger data chunks.",
            "" # Empty string
        ]

        print(f"Using AES Key (Base64): {base64.b64encode(key).decode('utf-8')}")
        print("--- Running 5 Test Cases ---")

        for i, plaintext in enumerate(test_cases):
            print(f"\nTest Case {i + 1}")
            print(f"Plaintext: {plaintext}")
            encrypted_text = encrypt(plaintext, key)
            print(f"Encrypted (Base64): {encrypted_text}")
            
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()