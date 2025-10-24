import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Per security guidelines (Rule #3, #4), AES-GCM is used as a secure
# authenticated encryption (AEAD) mode instead of the insecure AES-CBC.
# AES-GCM provides confidentiality, integrity, and authenticity.

# Constants for AES-256-GCM
KEY_BYTES = 32
NONCE_BYTES = 12  # Standard for GCM
TAG_BYTES = 16    # Standard for GCM


def create_aes_gcm_cipher_and_encrypt(encryption_key: bytes, data_to_encrypt: bytes) -> bytes:
    """
    Creates an AES-GCM cipher, encrypts data, and returns the encrypted result.

    This function provides a secure implementation using AES-256-GCM, which is an
    Authenticated Encryption with Associated Data (AEAD) mode. It is a secure
    alternative to legacy modes like CBC.

    Args:
        encryption_key: A 32-byte (256-bit) key for encryption.
        data_to_encrypt: The plaintext data (bytes) to encrypt.

    Returns:
        The encrypted data, formatted as: 12-byte nonce || ciphertext || 16-byte tag.
        This format contains all necessary information for decryption.

    Raises:
        ValueError: If the key is not 32 bytes long.
    """
    if len(encryption_key) != KEY_BYTES:
        raise ValueError(f"Encryption key must be {KEY_BYTES} bytes for AES-256.")

    # 1. Create a Cipher: The AESGCM object is the cipher instance.
    aesgcm = AESGCM(encryption_key)

    # 2. Generate a cryptographically secure random nonce. A new nonce MUST be
    #    used for every encryption operation with the same key.
    nonce = os.urandom(NONCE_BYTES)

    # 3. Encrypt the data.
    #    The `encrypt` method returns the ciphertext concatenated with the authentication tag.
    #    We do not use any Associated Data (AD) in this example, so it is set to None.
    encrypted_data = aesgcm.encrypt(nonce, data_to_encrypt, None)

    # 4. Return the result.
    #    Prepending the nonce to the ciphertext is a standard practice,
    #    as the nonce is required for decryption but does not need to be secret.
    return nonce + encrypted_data


def decrypt_with_aes_gcm(encryption_key: bytes, encrypted_payload: bytes) -> bytes:
    """
    Helper function to decrypt data for test case verification.

    Args:
        encryption_key: The 32-byte key used for encryption.
        encrypted_payload: The data from `create_aes_gcm_cipher_and_encrypt`,
                           which includes nonce, ciphertext, and tag.

    Returns:
        The original decrypted plaintext.

    Raises:
        ValueError: If the key is invalid, payload is malformed, or
                    if decryption fails due to an invalid authentication tag
                    (indicating tampering or incorrect key).
    """
    if len(encryption_key) != KEY_BYTES:
        raise ValueError(f"Encryption key must be {KEY_BYTES} bytes for AES-256.")

    if len(encrypted_payload) < NONCE_BYTES + TAG_BYTES:
        raise ValueError("Encrypted payload is too short to be valid.")

    # Extract the components from the payload
    nonce = encrypted_payload[:NONCE_BYTES]
    ciphertext_with_tag = encrypted_payload[NONCE_BYTES:]

    # Create the cipher
    aesgcm = AESGCM(encryption_key)

    try:
        # Decrypt and verify the tag simultaneously.
        # If the tag is invalid, `InvalidTag` is raised.
        decrypted_data = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return decrypted_data
    except InvalidTag:
        # This is a critical security check. If the tag is invalid, the data
        # has been tampered with, is corrupted, or the key is wrong.
        raise ValueError("Decryption failed: Authentication tag is invalid.")


def main():
    """
    Main function with 5 test cases for the AES-GCM encryption and decryption.
    """
    print("Running AES-256-GCM Encryption and Decryption Test Cases...")

    # For testing, we generate a random key using a cryptographically secure RNG.
    # In a real application, this key must be managed securely (e.g., in a vault).
    master_key = os.urandom(KEY_BYTES)

    test_cases = [
        b"This is a secret message.",
        b"Here is another message with a different length.",
        b"",  # Test case with empty plaintext
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", # Test binary data
        b"The final test case for our secure AES-GCM implementation!"
    ]

    for i, plaintext in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        print(f"Original Plaintext : {plaintext!r}")

        try:
            # Encrypt the plaintext
            encrypted_result = create_aes_gcm_cipher_and_encrypt(master_key, plaintext)
            print(f"Encrypted (hex)    : {encrypted_result.hex()}")

            # Decrypt to verify correctness
            decrypted_result = decrypt_with_aes_gcm(master_key, encrypted_result)
            print(f"Decrypted Plaintext: {decrypted_result!r}")

            # Assert that the decrypted text matches the original
            assert plaintext == decrypted_result
            print("SUCCESS: Decrypted data matches original plaintext.")

        except (ValueError, InvalidTag) as e:
            print(f"ERROR: An exception occurred during test case {i}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    # Additional test case to demonstrate tamper-proofing
    print("\n--- Tampering Test Case ---")
    tamper_plaintext = b"This data should not be tampered with."
    print(f"Original Plaintext: {tamper_plaintext!r}")
    encrypted_tamper = create_aes_gcm_cipher_and_encrypt(master_key, tamper_plaintext)
    
    # Tamper with the ciphertext by flipping a single bit
    tampered_list = bytearray(encrypted_tamper)
    # Flip a bit in the ciphertext part (after the 12-byte nonce)
    tampered_list[20] ^= 0x01 
    tampered_encrypted = bytes(tampered_list)

    print(f"Original Encrypted (hex) : {encrypted_tamper.hex()}")
    print(f"Tampered Encrypted (hex) : {tampered_encrypted.hex()}")

    try:
        decrypt_with_aes_gcm(master_key, tampered_encrypted)
    except ValueError as e:
        print(f"SUCCESS: Caught tampered message as expected. Error: {e}")


if __name__ == "__main__":
    main()